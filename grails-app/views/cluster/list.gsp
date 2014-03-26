<%--

    Copyright 2012 Netflix, Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

--%>
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
  <meta name="layout" content="main"/>
  <title>Clusters</title>
</head>
<body>
<div class="body">
  <h1>Clusters in ${region.description}${appNames ? ' for ' + appNames + '' : ''}</h1>
  <g:if test="${flash.message}">
    <div class="message">${flash.message}</div>
  </g:if>
  <g:form method="post">
    <div class="list">
      <div class="buttons">
        <g:link class="create" controller="autoScaling" action="create">Create New Auto Scaling Group</g:link>
      </div>
      <table class="sortable">
        <thead>
        <tr>
          <th>Cluster</th>
          <th>Auto Scaling Groups</th>
        </tr>
        </thead>
        <tbody>
        <g:each in="${clusters}" status="i" var="cluster">
          <tr class="${(i % 2) == 0 ? 'odd' : 'even'}">
            <g:if test="${cluster.name.contains('test')}">
                <td>
	                <g:linkObject class="none" type="cluster" name="${cluster.name}" title="Production Cluster">
	                    <img src="${resource(dir: 'edx/icomoon', file: 'rocket.svg')}"/>
	                </g:linkObject>
                </td>
            </g:if>
            <g:else>
                <td>
                    <g:linkObject class="none" type="cluster" name="${cluster.name}" title="Experimental Cluster">
                        <img src="${resource(dir: 'edx/icomoon', file: 'lab.svg')}"/>
                    </g:linkObject>
                </td>            
            </g:else>
            
            <td>
              <g:each var="group" in="${cluster.groups}">
                <g:linkObject type="autoScaling" name="${group.autoScalingGroupName}"/> (${group.instances.size()})<br>
              </g:each>
            </td>
          </tr>
        </g:each>
        </tbody>
      </table>
    </div>
  </g:form>
</div>
</body>
</html>
