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
package com.netflix.asgard

import org.apache.shiro.crypto.hash.Sha256Hash

class User {

	static auditable = true
	
    String username
    String passwordHash
    boolean enabled
    boolean accountExpired
    boolean accountLocked
    boolean passwordExpired
 
	static hasMany = [ roles: Role, permissions: String ]
        static mappedBy = [ roles: 'users' ]
    
		static constraints = {
        username(nullable: false, blank: false, unique: true)
    }

	private static User guestUser = null
	static final String defaultPass = "contour faddles arsonation repackaged"
	
	static User getGuestUser() {
		if (! guestUser) {
				guestUser = User.findByUsername('guest')
				if (! guestUser) {
						guestUser = new User(username: 'guest', passwordHash: new Sha256Hash(defaultPass).toHex()).save(flush: true, failOnError: true)
				}
		}
		return guestUser
	}	
	
    Set<Role> getAuthorities() {
        UserRole.findAllByUser(this).collect { it.role } as Set
    }
}
