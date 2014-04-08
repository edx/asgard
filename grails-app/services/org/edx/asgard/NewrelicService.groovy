package org.edx.asgard

import org.springframework.beans.factory.InitializingBean

import com.amazonaws.services.autoscaling.model.AutoScalingGroup;
import com.amazonaws.services.autoscaling.model.LaunchConfiguration
import com.amazonaws.services.ec2.model.Image
import com.netflix.asgard.AwsAutoScalingService;
import com.netflix.asgard.AwsEc2Service
import com.netflix.asgard.ConfigService
import com.netflix.asgard.From
import com.netflix.asgard.RestClientService
import com.netflix.asgard.UserContext
import com.netflix.asgard.push.GroupActivateOperation
import com.netflix.asgard.push.GroupCreateOptions

class NewrelicService implements InitializingBean {

    AwsEc2Service awsEc2Service
    AwsAutoScalingService awsAutoScalingService
    RestClientService restClientService
    ConfigService configService

    Map<String,String> apiHeaders = [:]

    public void afterPropertiesSet() throws Exception {
        String apiKey = configService.getNewrelicApiKey()
        apiHeaders << ['x-api-key':apiKey]
    }

    def deleteNewrelicServerRef() {
        def servers = restClientService.getAsXml(
            'https://api.newrelic.com/api/v1/accounts/88178/applications/2691834/servers.xml',
            1000,apiHeaders)
        log.error(servers)
    }

    def notifyOfDeployment(UserContext userContext, AutoScalingGroup asg) {
        def deploymentDetails = getDeploymentDetails(userContext,asg)
        restClientService.postAsNameValuePairs("https://api.newrelic.com/deployments.xml", deploymentDetails, apiHeaders)
    }
    
    def notifyOfAsgActivate(UserContext userContext, AutoScalingGroup asg) {
        getRevision(asg, userContext)
        getApplicationIdentifier(asg)
    }

    def notifyOfAsgDeactivate(UserContext userContext, AutoScalingGroup asg) {
        
    }

    def notifyOfAsgDelete(UserContext userContext, AutoScalingGroup asg) {
    
    }

    def notifyOfAsgResize(UserContext userContext, AutoScalingGroup asg) {
    
    }
    
    private Map<String, String> getDeploymentDetails(UserContext userContext, AutoScalingGroup asg) {
        def deploymentDetails = ["deployment[app_name]":getApplicationIdentifier(asg), "deployment[revision]":getRevision(asg, userContext)]
    }

    private String getRevision(AutoScalingGroup asg,UserContext userContext) {
        LaunchConfiguration launchConfig = awsAutoScalingService.getLaunchConfiguration(userContext, asg.launchConfigurationName,
                    From.CACHE)
        Image image = awsEc2Service.getImage(userContext, launchConfig.imageId, From.CACHE)

        def refTags = image.tags.findAll { it.key.endsWith("ref") }
        String foo = refTags.sort().join(",")
        return foo
    }
    private String getApplicationIdentifier(AutoScalingGroup asg) {
        def environment =asg.tags.environment ?: 'none'
        def deployment = asg.tags.deployment ?: 'none'
        def play = asg.tags.play ?: 'none'
        def edp = environment + "-" + deployment + "-" + play
    }
    
}
