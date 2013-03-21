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

import org.springframework.security.oauth2.provider.*

class OAuthClient {
	
	String clientId
	String resourceIds
	String clientSecret
	String scope
	String authorizedGrantTypes
	String webServerRedirectUri
	String authorities
	
	Date dateCreated
	
	static constraints = {
		clientId blank: false, nullable: false, unique: true
		scope nullable: true
		webServerRedirectUri nullable: true
		authorities nullable: true
	}
	
	static mapping = {
		version false
	}
	
	def toClientDetails() {
		def details = new BaseClientDetails(resourceIds, scope, authorizedGrantTypes, authorities)
		details.clientId = clientId
		details.clientSecret = clientSecret
		details.webServerRedirectUri = webServerRedirectUri
		details
	}
}