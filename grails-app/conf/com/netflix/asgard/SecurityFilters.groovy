package com.netflix.asgard

import com.netflix.asgard.User

import org.apache.shiro.SecurityUtils
import org.apache.shiro.authc.UsernamePasswordToken

class SecurityFilters  {
	/*
	 * check if guest permission is granted
	 */
	def guestControl(String permission) {
		def subject = SecurityUtils.subject
		if (subject.isAuthenticated())
			return false

		subject.login(new UsernamePasswordToken(User.guestUser.username, User.defaultPass))
		def ret = subject?.isPermitted(permission)
		subject.logout()
		return ret
	}

	def filters = {
		allow(controller: 'auth') {
			before = { true }
		}

		other(controllerExclude: 'auth') {
			before = {
				// Ignore direct views (e.g. the default main index page).
				if (!controllerName) return true

				// check if guest access (guest permission to domain:action:id) is granted
				// otherwise force user login and check if login user granted with appropriate permission
				String permission = "${controllerName}:${actionName}:${params.id}"
				if (guestControl(permission)) {
					return true
				} else {
					accessControl {
						def ret = SecurityUtils.subject?.isPermitted(permission)
						return ret
					}
				}
			}
		}
	}
}