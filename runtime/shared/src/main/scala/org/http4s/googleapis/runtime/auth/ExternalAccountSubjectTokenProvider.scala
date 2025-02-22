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
import cats.effect.Concurrent
import cats.syntax.all._
import fs2.io.file.Files
import fs2.io.file.Path
import io.circe.Decoder
import io.circe.parser
import org.http4s.circe.jsonOf

import CredentialsFile.ExternalAccount.ExternalCredentialUrlFormat
import CredentialsFile.ExternalAccount.ExternalCredentialUrlFormat.Text
import CredentialsFile.ExternalAccount.ExternalCredentialUrlFormat.{Json => JsonFmt}
import client.Client
private[auth] trait ExternalAccountSubjectTokenProvider {
  private[auth] def subjectTokenFromUrl[F[_]](
      client: Client[F],
      url: Uri,
      headers: Option[Map[String, String]],
      format: Option[ExternalCredentialUrlFormat],
  )(implicit F: Concurrent[F]) = {
    val headerList = headers.getOrElse(Map.empty).toList
    val hs = Headers(headerList)
    val req = Request[F](uri = url).putHeaders(hs)
    format match {
      // > If the format is not available, assume the external credential is provided in plain text format
      case None | Some(Text) => client.expect[String](req)
      case Some(JsonFmt(subjectTokenFieldName)) =>
        val dec = Decoder.forProduct1[String, String](subjectTokenFieldName)(identity)
        client.expect[String](req)(jsonOf(F, dec))
    }
  }
  private[auth] def subjectTokenFromFile[F[_]: Files](
      file: String,
      format: Option[ExternalCredentialUrlFormat],
  )(implicit F: Concurrent[F]) = for {
    tokenOrJson <- Files[F].readUtf8(Path(file)).compile.string
    tkn <- format match {
      // > If the format is not available, assume the external credential is provided in plain text format
      case None | Some(Text) => F.pure(tokenOrJson)
      case Some(JsonFmt(subjectTokenFieldName)) =>
        val dec = Decoder.forProduct1[String, String](subjectTokenFieldName)(identity)
        F.fromEither(parser.parse(tokenOrJson).flatMap(dec.decodeJson(_)))
    }
  } yield tkn
}
