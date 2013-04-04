/*
 * Copyright 2013 Physical Graph Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.code

import org.springframework.security.oauth2.common.exceptions.InvalidGrantException
import org.springframework.security.oauth2.common.util.*

class GormAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {
	
	void store(String code, UnconfirmedAuthorizationCodeAuthenticationTokenHolder authentication) {
		def oAuthCode = new oauth2.OAuthCode(
			code: code,
			authentication: SerializationUtils.serialize(authentication)
		)
		oauth2.OAuthCode.withTransaction { status ->
			oAuthCode.save()
		}
	}
	
	UnconfirmedAuthorizationCodeAuthenticationTokenHolder remove(String code) {
		def oAuthCode = oauth2.OAuthCode.findByCode code
		def authentication = null
		if (oAuthCode) {
			try {
				authentication = deserialize(oAuthCode.authentication)
			} catch (RuntimeException e) {
				log.error "Failed to deserialize authentication for code: $code"
				log.error e
			}
			oauth2.OAuthCode.withTransaction { status ->
				oAuthCode.delete()
			}
		}
		authentication
	}
	
	/**
	 * Need to pass the classLoader in on deserialization to avoid {@link java.lang.ClassNotFoundException}s for some classes.
	 *
	 * @param bytes The bytes to deserialize.
	 */
	def deserialize(bytes) {
		new java.io.ByteArrayInputStream(bytes).withObjectInputStream(getClass().classLoader) { ois ->
			ois.readObject()
		}
	}
	
}