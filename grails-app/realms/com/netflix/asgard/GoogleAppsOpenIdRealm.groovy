package com.netflix.asgard

import org.apache.shiro.authc.AuthenticationToken;

import com.netflix.asgard.auth.GoogleAppsOpenIdAuthenticationProvider.GoogleAppsOpenIdToken;

class GoogleAppsOpenIdRealm {

	static authTokenClass = GoogleAppsOpenIdToken

	def pluginService

	def authenticate(AuthenticationToken authToken) {
		pluginService.authenticationProvider.authenticate(authToken)
	}


}
