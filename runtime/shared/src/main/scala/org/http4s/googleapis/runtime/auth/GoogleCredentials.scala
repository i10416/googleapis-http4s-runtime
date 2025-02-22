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

package org.http4s.googleapis.runtime.auth

/** Generic interface for Google credentials to obtain access token, which is attached to
  * headers of requests to GCP services.
  */
trait GoogleCredentials[F[_]] {

  /** obtain quota project id if any.
    */
  def projectId: Option[String]
  def get: F[AccessToken]
}
