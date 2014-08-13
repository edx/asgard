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

class Role {

    static auditable = true

    String name
    //User createdBy
    //Date dateCreated
    String authority

    static hasMany = [ users: User, permissions: String ]
    static belongsTo = User

    static mapping = {
        cache true
    }

    static constraints = {
        authority nullable: true, blank: true, unique: true
    }

    private static Role publicRole = null
    private static Role authRole = null
    private static Role adminRole = null

    static Role getAdminRole() {
        if (! adminRole) {
            adminRole = Role.findByName('admin')
            if (! adminRole) {
                adminRole = new Role(name: 'admin').addToPermissions('*').save(flush: true, failOnError: true)
            }
        }
        return adminRole
    }

    /*
     * return authenticated user role with all real users assigned to (i.e. guest is not defined as authRole user)
     */
    static Role getAuthRole() {
        if (! authRole) {
            authRole = Role.findByName('auth')
            if (! authRole) {
                authRole = new Role(name: 'auth').save(flush: true, failOnError: true)
            }
        }
        return authRole
    }

    /*
     * return public role with all system users assigned to
     */
    static Role getPublicRole() {
        if (! publicRole) {
            publicRole = Role.findByName('public')
            if (! publicRole) {
                publicRole = new Role(name: 'public').save(flush: true, failOnError: true)
            }
        }
        return publicRole
    }
}
