/*
 * Copyright 2012 Netflix, Inc.
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
package com.netflix.asgard.auth

import java.util.regex.Pattern;

import groovy.json.JsonSlurper

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpSession

import org.apache.shiro.authc.AuthenticationException
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.RememberMeAuthenticationToken
import org.apache.shiro.authc.SimpleAuthenticationInfo
import org.apache.shiro.crypto.hash.Sha256Hash
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsParameterMap
import org.openid4java.message.ParameterList
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.Token
import org.scribe.model.Verifier
import org.scribe.oauth.OAuthService;

import sun.invoke.util.VerifyType;
import uk.co.desirableobjects.oauth.scribe.OauthService

import org.springframework.beans.factory.annotation.Autowired

import uk.co.desirableobjects.oauth.scribe.OauthProvider
import uk.co.desirableobjects.oauth.scribe.SupportedOauthVersion

import com.netflix.asgard.ConfigService
import com.netflix.asgard.Role
import com.netflix.asgard.User
import com.netflix.asgard.plugin.AuthenticationProvider

class GithubOauthAuthenticationProvider implements AuthenticationProvider {

	public static final String PROVIDER_NAME = "github"

	private static final Token EMPTY_TOKEN = null
	private static final String VERIFIER_KEY = "code"
		
    @Autowired
    ConfigService configService

    @Autowired
    OauthService oauthService

    @Override
    public String loginUrl(HttpServletRequest request) {
 
		def requestToken = EMPTY_TOKEN
		
		OAuthService service = new ServiceBuilder().provider(GitHubApi.class)
		.apiKey(configService.githubApiKey)
		.apiSecret(configService.githubApiSecret)
		.callback(configService.githubApiCallback).build()

		def scope = configService.githubApiScope
		
        def session = request.getSession()
        session[oauthService.findSessionKeyForRequestToken(PROVIDER_NAME)] = requestToken
        String url = oauthService.getAuthorizationUrl(PROVIDER_NAME, requestToken)
		return url + "&scope=${scope}"
    }

    @Override
    public String logoutUrl(HttpServletRequest request) {
        return GitHubApi.LOGOUT_URL
    }

    @Override
    public AsgardToken tokenFromRequest(HttpServletRequest request) {
        // extract the parameters from the authentication response
        ParameterList openidResp = new ParameterList(request.getParameterMap())

        GrailsParameterMap paramMap = new GrailsParameterMap(request)
        HttpSession session = request.getSession()

        OauthProvider provider = oauthService.findProviderConfiguration(PROVIDER_NAME)

        Verifier verifier = extractVerifier(provider, paramMap)

        if (!verifier) {
            throw new AuthenticationException("not authenticated")
        }

        Token requestToken = (Token) session[oauthService.findSessionKeyForRequestToken(PROVIDER_NAME)]
        Token accessToken = oauthService.getAccessToken(PROVIDER_NAME, requestToken, verifier)

        session[oauthService.findSessionKeyForAccessToken(PROVIDER_NAME)] = accessToken
        session.removeAttribute(oauthService.findSessionKeyForRequestToken(PROVIDER_NAME))

        if (accessToken == null) {
            throw new AuthenticationException("Access token cannot be null.")
        }

        Token githubAccessToken = (Token) session[oauthService.findSessionKeyForAccessToken(PROVIDER_NAME)]

        GithubToken token = new GithubToken(githubAccessToken)

		// A local GORM model needs to exist in order to associate roles with users
		// for RBAC. These records will not survive a restart, but will automatically
		// be recreated.
		// 
		// TODO: ultimately this should be obviated
		// 
		if (! User.findByUsername(token.principal)) {
			def user = new User(username: token.principal, passwordHash: new Sha256Hash(User.defaultPass).toHex())
			user.addToRoles(Role.adminRole)
			user.save(flush: true)
		}
		
        return token
    }

    private Verifier extractVerifier(OauthProvider provider, GrailsParameterMap params) {

        if (!params[VERIFIER_KEY]) {
            log.error("Cannot authenticate with oauth: Could not find oauth verifier in ${params}.")
            return null
        }

        String verification = params[VERIFIER_KEY]
        return new Verifier(verification)

    }

    @Override
    AuthenticationInfo authenticate(AsgardToken authToken) {

		GithubToken githubToken = (GithubToken) authToken
		
		if (null == githubToken) {
			throw new AuthenticationException("Authentication token cannot be null.")
		}
		
		if (! githubToken.isValid()) {
			throw new AuthenticationException("Authentication token is invalid")
		}
		
        new SimpleAuthenticationInfo(authToken.principal, authToken.credentials, 'AsgardRealm')
    }

    class GithubToken implements AsgardToken, RememberMeAuthenticationToken {

		private static final String USER_SCOPE = "https://api.github.com/user"
		private static final String USER_EMAILS_SCOPE = "https://api.github.com/user/emails"
		private static final String USER_TEAMS_SCOPE = "https://api.github.com/user/teams"
		
        private Object credentials
        private String principal
        private boolean valid = false

        public GithubToken(Token t) {
			
			def githubPrincipal = getOrgAffiliatedEmail(configService.githubApiEmailRegex, t.token)
			verify2faStatus(githubPrincipal.login, configService.githubApiOrganization, t.token)
			verifyTeam(configService.githubApiOrganizationId, configService.githubApiTeamRegex, t.token)
			// TODO potentially this should be expanded, but needs testing to ensure that 
			// New Relic is not broken by changing the type from String to Map or Object
            this.principal = githubPrincipal.email
            this.credentials = t
            this.valid = true
        }

		private Map getOrgAffiliatedEmail(emailRegex, token) {

			def userData = getAPIModel(USER_SCOPE, token)
							
			def emailData = getAPIModel(USER_EMAILS_SCOPE, token)
					
			def authenticatedUsersEmail = emailData.find { it.verified && it.email =~ emailRegex }
		
			if (! authenticatedUsersEmail) {
				throw new AuthenticationException('No valid principal ')
			}
							
			return [login:userData.login, email: authenticatedUsersEmail.email]
			
		}
		
		private void verifyTeam(orgId, teamRegex, token) {

			def teamData = getAPIModel(USER_TEAMS_SCOPE, token)
						
			def teamModel = teamData.find { it.name =~ teamRegex }
			
			if ( ! teamModel ) {
				throw new AuthenticationException('Principal not associated with the appropriate team.')
			}

			if ( ! teamModel?.organization?.id == orgId ) {
				throw new AuthenticationException('Group not associated with the appropriate org.')
			}			
		}
		
		private void verify2faStatus(login, org, token) {

			String org2faStatus = "https://api.github.com/orgs/${org}/members?filter=\\2fa_disabled"
			
			def disabled2fa = getAPIModel(org2faStatus, token)
			def  login2faDisabled = disabled2fa.find { it.login == login }
			
			// If the value returned from find is not null the user existed
			// in the list of users for the org with 2FA unenabled
			if ( login2faDisabled ) {
				throw new AuthenticationException("Access denied as user does not have 2FA enabled for their account.")
			}
		}
		
		private Object getAPIModel(apiTarget, token) {
			
			def textResponse = apiTarget.toURL()
				.getText(requestProperties: [Authorization: "token " + token])
		
			return (new JsonSlurper()).parseText(textResponse)
		}
		
        @Override
        public Object getCredentials() {
            return this.credentials
        }

        @Override
        public Object getPrincipal() {
            return this.principal
        }

        public isValid() {
            return this.valid
        }

        @Override
        public boolean isRememberMe() {
            return true
        }

    }

}
