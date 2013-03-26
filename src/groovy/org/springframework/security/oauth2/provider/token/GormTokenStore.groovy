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
package org.springframework.security.oauth2.provider.token

import org.apache.commons.logging.LogFactory

import org.springframework.security.oauth2.common.*
import org.springframework.security.oauth2.common.util.*
import org.springframework.security.oauth2.provider.*

/**
 * Implementation of token services that stores tokens in a database through GORM.
 * 
 * Modeled after {@link org.springframework.security.oauth2.provider.token.JdbcTokenStore}.
 */
class GormTokenStore implements TokenStore {
	
	static final log = LogFactory.getLog(this)
	
	/**
	 * Read the authentication stored under the specified token value.
	 *
	 * @param token The token value under which the authentication is stored.
	 * @return The authentication, or null if none.
	 */
	OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		def accessToken = oauth2.OAuthAccessToken.findByTokenId token.value
		def authentication = null
		if (accessToken) {
			try {
				authentication = deserialize(accessToken.authentication)
			} catch (RuntimeException e) {
				log.error "Failed to deserialize authentication for token: $token"
				log.error e
			}
		} else {
			log.info "Failed to find access token for token: $token"
		}
		authentication
	}

	/**
	 * Store an access token.
	 *
	 * @param token		  The token to store.
	 * @param authentication The authentication associated with the token.
	 */
	void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		def accessToken = new oauth2.OAuthAccessToken(
			tokenId: token.value,
			expiration: token.expiration,
			tokenType: token.tokenType,
			authentication: SerializationUtils.serialize(authentication),
			refreshToken: token.refreshToken?.value,
			username: authentication.name
		)
		accessToken.populateScope(token.scope)
		oauth2.OAuthAccessToken.withTransaction { status ->
			accessToken.save()
		}
	}

	/**
	 * Read an access token from the store.
	 *
	 * @param tokenValue The token value.
	 * @return The access token to read.
	 */
	OAuth2AccessToken readAccessToken(String tokenValue) {
		def accessToken = oauth2.OAuthAccessToken.findByTokenId tokenValue
		def token = null
		if (accessToken) {
			log.debug "Found access token for token: $tokenValue"
			token = accessToken.toAccessToken()
		} else {
			log.info "Failed to find access token for token: $tokenValue"
		}
		token
	}

	/**
	 * Remove an access token from the database.
	 *
	 * @param tokenValue The token to remove from the database.
	 */
	void removeAccessToken(String tokenValue) {
		def accessToken = oauth2.OAuthAccessToken.findByTokenId tokenValue
		if (accessToken) {
			oauth2.OAuthAccessToken.withTransaction { status ->
				accessToken.delete()
			}
		}
	}

	/**
	 * Read the authentication stored under the specified token value.
	 *
	 * @param token The token value under which the authentication is stored.
	 * @return The authentication, or null if none.
	 */
	OAuth2Authentication readAuthentication(ExpiringOAuth2RefreshToken token) {
		def expiringRefreshToken = oauth2.OAuthRefreshToken.findByTokenId token.value
		def authentication = null
		if (expiringRefreshToken) {
			log.debug "Found refresh token for token: $token.value"
			try {
				authentication = deserialize(expiringRefreshToken.authentication)
			} catch (RuntimeException e) {
				log.error "Failed to deserialize authentication for token: $token"
				log.error e
			}
		} else {
			log.info "Failed to find refresh token for token: $token"
		}
		authentication
	}

	/**
	 * Store the specified refresh token in the database.
	 *
	 * @param token          The refresh token to store.
	 * @param authentication The authentication associated with the refresh token.
	 */
	void storeRefreshToken(ExpiringOAuth2RefreshToken token, OAuth2Authentication authentication) {
		def refreshToken = new oauth2.OAuthRefreshToken(
			tokenId: token.value,
			expiration: token.expiration,
			authentication: SerializationUtils.serialize(authentication),
			username: authentication.name
		)
		oauth2.OAuthRefreshToken.withTransaction { status ->
			refreshToken.save()
		}
	}

	/**
	 * Read a refresh token from the store.
	 *
	 * @param tokenValue The value of the token to read.
	 * @return The token.
	 */
	ExpiringOAuth2RefreshToken readRefreshToken(String tokenValue) {
		def refreshToken = oauth2.OAuthRefreshToken.findByTokenId tokenValue
		def token = null
		if (refreshToken) {
			log.debug "Found refresh token for token: $tokenValue"
			token = refreshToken.toRefreshToken()
		} else {
			log.info "Failed to find refresh token for token: $tokenValue"
		}
		token
	}

	/**
	 * Remove a refresh token from the database.
	 *
	 * @param tokenValue The value of the token to remove from the database.
	 */
	void removeRefreshToken(String tokenValue) {
		def refreshToken = oauth2.OAuthRefreshToken.findByTokenId tokenValue
		if (refreshToken) {
			oauth2.OAuthRefreshToken.withTransaction { status ->
				refreshToken.delete()
			}
		}
	}

	/**
	 * Remove an access token using a refresh token. This functionality is necessary so refresh tokens can't be used to create an unlimited number of
	 * access tokens.
	 *
	 * @param refreshToken The refresh token.
	 */
	void removeAccessTokenUsingRefreshToken(String refreshToken) {
		def accessToken = oauth2.OAuthAccessToken.findByRefreshToken refreshToken
		if (accessToken) {
			oauth2.OAuthAccessToken.withTransaction { status ->
				accessToken.delete()
			}
		}
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