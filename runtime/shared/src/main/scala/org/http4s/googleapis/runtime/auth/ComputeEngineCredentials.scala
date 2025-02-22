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
import cats.syntax.all._
import org.http4s.googleapis.runtime.ComputeMetadata

/** ComputeEngineCredentials is credentials that associated with a service account attached to
  * an instance of Google Compute Engine and its family(e.g. Cloud Run and Cloud Functions).
  */
object ComputeEngineCredentials {
  def apply[F[_]](met: ComputeMetadata[F])(implicit
      F: Temporal[F],
  ): F[GoogleCredentials[F]] =
    for {
      pid <- met.getProjectId
      credentials <- Oauth2Credentials(Some(pid), met.getAccessToken)
    } yield credentials
}
