/*
 * Copyright 2013 Netflix, Inc.
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

import com.amazonaws.services.ec2.model.GroupIdentifier
import com.amazonaws.services.ec2.model.SecurityGroup
import grails.test.mixin.TestFor
import spock.lang.Specification

@TestFor(ObjectLinkTagLib)
class ObjectLinkTagLibSpec extends Specification {

    def 'should generate link'() {
        when:
        grailsApplication.metaClass.getControllerNamesToContextParams = { -> ['instance': []] }
        String output = applyTemplate('<g:linkObject type="instance" name="i-12345678">aprop</g:linkObject>')

        then:
        output == '<a href="/instance/show/i-12345678" ' +
                'title="Show details of this Instance" class="instance">aprop i-12345678</a>'
    }

    def 'should generate fast property link'() {
        when:
        grailsApplication.metaClass.getControllerNamesToContextParams = { -> ['fastProperty': []] }
        String output = applyTemplate('<g:linkObject type="fastProperty" name="|prop:8888">aprop</g:linkObject>')

        then:
        output == '<a href="/fastProperty/show?name=%7Cprop%3A8888" ' +
                'title="Show details of this Fast Property" class="fastProperty">aprop |prop:8888</a>'
    }

    def 'should generate link for SQS subscription endpoint in same account'() {
        grailsApplication.metaClass.getControllerNamesToContextParams = { -> ['queue': []] }
        tagLib.configService = Mock(ConfigService) {
            getAwsAccountNumber() >> '170000000000'
        }

        expect:
        applyTemplate(template) == result

        where:
        template                                                                                                | result
        '<g:snsSubscriptionEndpoint>jsnow@thewall.got</g:snsSubscriptionEndpoint>'                              |
                'jsnow@thewall.got'
        '<g:snsSubscriptionEndpoint>arn:aws:sqs:us-west-1:170000000001:testSQSWest</g:snsSubscriptionEndpoint>' |
                'arn:aws:sqs:us-west-1:170000000001:testSQSWest'
        '<g:snsSubscriptionEndpoint>arn:aws:sqs:us-west-1:170000000000:testSQSWest</g:snsSubscriptionEndpoint>' |
                '<a href="/queue/show/testSQSWest" region="us-west-1" title="Show details of this Queue" ' +
                'class="queue">arn:aws:sqs:us-west-1:170000000000:testSQSWest testSQSWest</a>'
    }

    def 'should generate security group link with name and id displayed using duck typing of security object'() {

        grailsApplication.metaClass.getControllerNamesToContextParams = { -> ['security': []] }

        when:
        String output = applyTemplate('<g:securityGroup group="${securityGroup}"/>', [securityGroup: input])

        then:
        output == '<a href="/security/show/sg-1234" title="Show details of this Security Group" ' +
                'class="security">vampire (sg-1234) sg-1234</a>'

        where:
        input << [
                new SecurityGroup(groupName: 'vampire', groupId: 'sg-1234'),
                new GroupIdentifier(groupName: 'vampire', groupId: 'sg-1234'),
                [groupName: 'vampire', groupId: 'sg-1234'],
        ]
    }
}
