package org.edx.asgard

import org.springframework.beans.factory.InitializingBean

import com.amazonaws.services.autoscaling.model.AutoScalingGroup
import com.amazonaws.services.autoscaling.model.LaunchConfiguration
import com.amazonaws.services.autoscaling.model.TagDescription
import com.amazonaws.services.ec2.model.Image
import com.netflix.asgard.AwsAutoScalingService
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

    def notifyOfAsgCreate(UserContext userContext, AutoScalingGroup asg) {
        def deploymentDetails = getDeploymentDetails(userContext,asg,"Create ASG")
        restClientService.postAsNameValuePairs("https://api.newrelic.com/deployments.xml", deploymentDetails, apiHeaders)
    }
    
    def notifyOfAsgActivate(UserContext userContext, AutoScalingGroup asg) {
        def deploymentDetails = getDeploymentDetails(userContext,asg,"Activate ASG")
        restClientService.postAsNameValuePairs("https://api.newrelic.com/deployments.xml", deploymentDetails, apiHeaders)
    }

    def notifyOfAsgDeactivate(UserContext userContext, AutoScalingGroup asg) {
        def deploymentDetails = getDeploymentDetails(userContext,asg,"Deactivate ASG")
        restClientService.postAsNameValuePairs("https://api.newrelic.com/deployments.xml", deploymentDetails, apiHeaders)
    }

    def notifyOfAsgDelete(UserContext userContext, AutoScalingGroup asg) {
        def deploymentDetails = getDeploymentDetails(userContext,asg,"Delete ASG")
        restClientService.postAsNameValuePairs("https://api.newrelic.com/deployments.xml", deploymentDetails, apiHeaders)
    }

    def notifyOfAsgResize(UserContext userContext, AutoScalingGroup asg) {
        def deploymentDetails = getDeploymentDetails(userContext,asg,"Resize ASG")
        restClientService.postAsNameValuePairs("https://api.newrelic.com/deployments.xml", deploymentDetails, apiHeaders)
    }
    
    private Map<String, String> getDeploymentDetails(UserContext userContext, AutoScalingGroup asg, String eventType) {
        def deploymentDetails = ["deployment[app_name]":getApplicationIdentifier(asg), 
            "deployment[revision]":eventType + " from ticket: " + userContext.ticket,
            "deployment[user]":userContext.username,
            "deployment[description]":eventType,
            "deployment[changelog":getRevision(asg, userContext)]
    }

    private String getRevision(AutoScalingGroup asg,UserContext userContext) {
        LaunchConfiguration launchConfig = awsAutoScalingService.getLaunchConfiguration(userContext, asg.launchConfigurationName,
                    From.CACHE)
        Image image = awsEc2Service.getImage(userContext, launchConfig.imageId, From.CACHE)
        def refs = image.tags.findAll { it.key.endsWith("ref") || it.key.startsWith("ref") }
        def cleanRefs = []
        refs.sort().each( { cleanRefs << "${it.key}=${it.value}" } )
        return cleanRefs.join("\n")

    }
    private String getApplicationIdentifier(AutoScalingGroup asg) {

        List tags = asg.tags.findAll({ ['environment','deployment','play'].contains(it.getKey()) })

        def environment = "no_environment"
        def deployment = "no_deployment"
        def play = "no_play"

        if (tags.size()==3) {
            Map<String,TagDescription> tagMap = new HashMap<String,TagDescription>()
            tags.each { tagMap.put( it.getKey(), it ) }
            environment = tagMap.get("environment").getValue()
            deployment = tagMap.get("deployment").getValue()
            play = tagMap.get("play").getValue()
        }

        //return "${environment}-${deployment}-${play}"
        return "dev-worker"
    }

}
