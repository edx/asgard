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
import org.scribe.model.Token
import org.scribe.model.Verifier

import uk.co.desirableobjects.oauth.scribe.OauthService

import org.springframework.beans.factory.annotation.Autowired

import uk.co.desirableobjects.oauth.scribe.OauthProvider
import uk.co.desirableobjects.oauth.scribe.SupportedOauthVersion

import com.netflix.asgard.ConfigService
import com.netflix.asgard.Role
import com.netflix.asgard.User
import com.netflix.asgard.plugin.AuthenticationProvider

class GoogleOpenIdConnectAuthenticationProvider implements AuthenticationProvider {

    private final Token EMPTY_TOKEN = null

    @Autowired
    ConfigService configService

    @Autowired
    OauthService oauthService

    @Override
    public String loginUrl(HttpServletRequest request) {
        String providerName = "google"

        OauthProvider provider = oauthService.findProviderConfiguration(providerName)

        Token requestToken = EMPTY_TOKEN
        if (provider.getOauthVersion() == SupportedOauthVersion.ONE) {
            requestToken = provider.service.requestToken
        }

        def session = request.getSession()
        session[oauthService.findSessionKeyForRequestToken(providerName)] = requestToken
        return oauthService.getAuthorizationUrl(providerName, requestToken)
    }

    @Override
    public String logoutUrl(HttpServletRequest request) {
        return "https://www.google.com/accounts/Logout";
    }

    @Override
    public AsgardToken tokenFromRequest(HttpServletRequest request) {
        // extract the parameters from the authentication response
        // (which comes in as a HTTP request from the OpenID provider)
        ParameterList openidResp = new ParameterList(request.getParameterMap())

        GrailsParameterMap paramMap = new GrailsParameterMap(request)
        HttpSession session = request.getSession()

        String providerName = "google"
        OauthProvider provider = oauthService.findProviderConfiguration(providerName)

        Verifier verifier = extractVerifier(provider, paramMap)

        if (!verifier) {
            throw new AuthenticationException("not authenticated")
        }

        Token requestToken = (Token) session[oauthService.findSessionKeyForRequestToken(providerName)]
        Token accessToken = oauthService.getAccessToken(providerName, requestToken, verifier)

        session[oauthService.findSessionKeyForAccessToken(providerName)] = accessToken
        session.removeAttribute(oauthService.findSessionKeyForRequestToken(providerName))

        if (accessToken == null) {
            throw new AuthenticationException()
        }

        Token googleAccessToken = (Token) session[oauthService.findSessionKeyForAccessToken('google')]

        GoogleOpenIdConnectToken goct = new GoogleOpenIdConnectToken(googleAccessToken)

        if (! configService.getAdministrators().contains(goct.principal)) {
            throw new AuthenticationException("User ${goct.principal} is not on the whitelist")
        }

        if (! User.findByUsername(goct.principal)) {
            def user = new User(username: goct.principal, passwordHash: new Sha256Hash(User.defaultPass).toHex())
            user.addToRoles(Role.adminRole)
            user.save(flush: true)
        }

        return goct
    }

    private Verifier extractVerifier(OauthProvider provider, GrailsParameterMap params) {

        String verifierKey = 'oauth_verifier'
        if (SupportedOauthVersion.TWO == provider.oauthVersion) {
            verifierKey = 'code'
        }

        if (!params[verifierKey]) {
            log.error("Cannot authenticate with oauth: Could not find oauth verifier in ${params}.")
            return null
        }

        String verification = params[verifierKey]
        return new Verifier(verification)

    }

    @Override
    AuthenticationInfo authenticate(AsgardToken authToken) {

        new SimpleAuthenticationInfo(authToken.principal, authToken.credentials, 'GoogleAppsOpenIdRealm')
    }

    class GoogleOpenIdConnectToken implements AsgardToken, RememberMeAuthenticationToken {

        static String SCOPE="https://www.googleapis.com/userinfo/v2/me"

        Object credentials
        String principal
        boolean valid = false

        public GoogleOpenIdConnectToken(Token t) {
//            def json = SCOPE.toURL().
//                    getText(requestProperties: [Authorization: "Bearer " + t.token])
//
//            def googleResponse = (new JsonSlurper()).parseText(json)
        
            this.principal = 'none@edx.org'
            this.credentials = t
            this.valid = true
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
