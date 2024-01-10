/*
 * Copyright 2024 Yoichiro Ito
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.http4s
package googleapis.runtime.auth

import cats.effect.Temporal
import io.circe.Json
import io.circe.syntax._
import org.http4s.circe.jsonEncoderOf

import googleapis.runtime.auth.CredentialsFile.ExternalAccount
import client.Client
import headers.`Content-Type`

/** googleOAuth2TokenExchange enables to fetch Google access token from external credentials.
  */
trait GoogleOAuth2TokenExchange[F[_]] {

  /** Exchanges the external credential for a Google Cloud access token.
    * @param subjectToken
    *   A security token that represents the identity of the party on behalf of whom the request
    *   is being made.
    * @param scopes
    *   a list of OAuth scopes that specify the desired scopes of the requested security token
    *   in the context of the service or resource where the token should be used. If service
    *   account impersonation is used, the cloud platform or IAM scope should be passed.
    * @param requestOverride
    *   A hack to support Secure Token Service that requires dedicated handling. For example,
    *   AWS STS requires `x-goog-cloud-endpoint` header.
    * @param resource
    *   A URI that indicates the target service or resource where the client intends to use the
    *   requested security token.
    * @return
    *   the access token returned by the Security Token Service
    *
    * @see
    *   https://tools.ietf.org/html/rfc8693#section-2.1 and
    *   https://tools.ietf.org/html/rfc8693#section-2.2.1
    */
  def stsToken(
      subjectToken: String,
      externalAccount: ExternalAccount,
      scopes: Seq[String],
      resource: Option[String] = None,
      actingParty: Option[ActingParty] = None,
      requestOverride: Request[F] => Request[F] = identity,
  ): F[AccessToken]
}

object GoogleOAuth2TokenExchange {
  def apply[F[_]: Temporal](client: Client[F]) =
    new GoogleOAuth2TokenExchange[F] {
      private val je: EntityEncoder[F, Json] = jsonEncoderOf[F, Json]
      def stsToken(
          subjectToken: String,
          externalAccount: ExternalAccount,
          scopes: Seq[String],
          resource: Option[String] = None,
          actingParty: Option[ActingParty] = None,
          requestOverride: Request[F] => Request[F] = identity,
      ): F[AccessToken] = {
        val req = Request[F](
          uri = Uri.unsafeFromString(externalAccount.token_url),
          method = Method.POST,
        )
          .withHeaders(
            `Content-Type`(MediaType.application.json),
          )
          .withEntity(
            Json
              .obj(
                "grant_type" -> Json.fromString(
                  "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                "audience" -> Json.fromString(externalAccount.audience),
                "requested_token_type" -> Json.fromString(
                  "urn:ietf:params:oauth:token-type:access_token",
                ),
                "subject_token_type" -> Json.fromString(externalAccount.subject_token_type),
                "subject_token" -> Json.fromString(subjectToken),
                "scope" -> Json.fromString(scopes.mkString(" ")),
              )
              .deepMerge(
                resource.fold(Json.obj())(r => ("resource" -> r.asJson).asJson),
              )
              .deepMerge(
                actingParty
                  .fold(Json.obj())(a => ("actor_token" -> a.actorToken.asJson).asJson),
              )
              .deepMerge(
                actingParty.fold(Json.obj())(a =>
                  ("actor_token_type" -> a.actorTokenType.asJson).asJson,
                ),
              ),
          )(je)
        // unsafe because `expires_in` field is optional in spec.
        client.expect[AccessToken](requestOverride(req))
      }
    }
}

/** @param actorToken
  *   A security token that represents the identity of the acting party. Typically, this will be
  *   the party that is authorized to use the requested security token and act on behalf of the
  *   subject.
  * @param actorTokenType
  *   An identifier, as described in Section 3, that indicates the type of the security token in
  *   the "actor_token" parameter. This is REQUIRED when the "actor_token" parameter is present
  *   in the request but MUST NOT be included otherwise.
  */
case class ActingParty(
    actorToken: String,
    actorTokenType: String,
)
