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
package oauth2

import org.springframework.security.oauth2.common.OAuth2AccessToken

class OAuthAccessToken {
	
	String tokenId
	Date expiration
	String tokenType
	String scope
	byte[] authentication
	String refreshToken
	String username
	
	Date dateCreated
	
	static constraints = {
		tokenId blank: false, nullable: false, unique: true
		refreshToken nullable: true
	}
	
	static mapping = {
		version false
	}
	
	def populateScope(scopeSet) {
		def scopeString = ""
		scopeSet?.each { scope ->
			scopeString += scope + " "
		}
		this.scope = scopeString.trim()
	}
	
	def toToken() {
		def token = new OAuth2AccessToken(tokenId)
		token.expiration = expiration
		token.tokenType = tokenType
		if (refreshToken) {
			token.refreshToken = OAuthRefreshToken.findByTokenId(refreshToken)?.toToken()
		}
		
		def scopeSet = new HashSet<String>();
		scope?.split()?.each { scopePart ->
			scopeSet.add scopePart
		}
		token.scope = scopeSet
		token
	}
}