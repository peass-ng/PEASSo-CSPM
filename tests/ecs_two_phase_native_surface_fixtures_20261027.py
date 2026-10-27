"""Exact public synthetic fixture functions copied without unrelated registry consumers."""
import base64,json
from datetime import datetime,timezone
ACCOUNT="123456789012";REGION="us-east-1";SCOPE=ACCOUNT+"/"+REGION
TOKEN="ghp_"+"7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT"
NOW=datetime(2026,10,20,tzinfo=timezone.utc)
def arn(service,resource):return f'arn:aws:{service}:{REGION}:{ACCOUNT}:{resource}'

def encoded(text):return base64.b64encode(text.encode()).decode()

def metadata():return {'HTTPStatusCode':200,'RequestId':'11111111-1111-4111-8111-111111111111','HTTPHeaders':{'echo':TOKEN}}

def native(surface,positive=False,*,name='AuditResource'):
    text='TOKEN='+TOKEN if positive else 'MODE=production'
    value=TOKEN if positive else 'production'
    target={'surface':surface,'scope':SCOPE}
    if surface=='cloudformation_template':
        target['resource_id']=arn('cloudformation','stack/'+name+'/11111111-1111-4111-8111-111111111111')
        responses=[{'TemplateBody':json.dumps({'AWSTemplateFormatVersion':'2010-09-09',
            'Resources':{'Review':{'Type':'AWS::CloudFormation::WaitConditionHandle'}},
            'Outputs':{'ReviewValue':{'Value':value}}}),'StagesAvailable':['Original']}]
    elif surface=='codepipeline_configuration':
        target.update(resource_id=arn('codepipeline',name),version=3)
        responses=[{'pipeline':{'name':name,'roleArn':'arn:aws:iam::'+ACCOUNT+':role/pipeline-reader',
            'artifactStore':{'type':'S3','location':'offline-artifacts'},'version':3,
            'stages':[{'name':'Build','actions':[{'name':'Review','actionTypeId':{
                'category':'Build','owner':'AWS','provider':'CodeBuild','version':'1'},
                'configuration':{'ProjectName':name,'EnvironmentVariables':json.dumps([
                    {'name':'TOKEN' if positive else 'MODE','value':value,'type':'PLAINTEXT'}])}}]}]},
            'metadata':{'pipelineArn':target['resource_id'],'created':NOW,'updated':NOW}}]
    elif surface=='cloudformation_outputs':
        target['resource_id']=arn('cloudformation','stack/'+name+'/11111111-1111-4111-8111-111111111111')
        responses=[{'Stacks':[{'StackId':target['resource_id'],'StackName':name,'StackStatus':'CREATE_COMPLETE','CreationTime':NOW,'Description':TOKEN,
                   'Outputs':[{'OutputKey':'TOKEN' if positive else 'MODE','OutputValue':value,'Description':TOKEN}]}]}]
    elif surface=='codebuild_environment':
        target['resource_id']=arn('codebuild','project/'+name)
        responses=[{'projects':[{'name':name,'arn':target['resource_id'],'description':TOKEN,
          'source':{'type':'NO_SOURCE'},'artifacts':{'type':'NO_ARTIFACTS'},
          'environment':{'type':'LINUX_CONTAINER','image':'aws/codebuild/standard:7.0','computeType':'BUILD_GENERAL1_SMALL',
                         'environmentVariables':[{'name':'TOKEN' if positive else 'MODE','value':value,'type':'PLAINTEXT'}]}}]}]
    elif surface=='rest_stage_variables':
        target['resource_id']=f'arn:aws:apigateway:{REGION}::/restapis/a1b2c3/stages/'+name
        responses=[{'stageName':name,'description':TOKEN,'variables':{'TOKEN' if positive else 'MODE':value}}]
    elif surface=='ecs_environment':
        target['resource_id']=arn('ecs','task-definition/'+name+':3')
        responses=[{'taskDefinition':{'taskDefinitionArn':target['resource_id'],'family':name,'revision':3,'status':'ACTIVE',
           'containerDefinitions':[{'name':'app','image':'public.ecr.aws/example/app:latest','environment':[{'name':'TOKEN' if positive else 'MODE','value':value}]}]}}]
    elif surface=='amplify_environment':
        target['resource_id']=arn('amplify','apps/d1abc123')
        responses=[{'app':{'appId':'d1abc123','appArn':target['resource_id'],'name':name,'description':TOKEN,'repository':'',
          'platform':'WEB','createTime':NOW,'updateTime':NOW,'environmentVariables':{'TOKEN' if positive else 'MODE':value},
          'defaultDomain':'d1abc123.amplifyapp.com','enableBranchAutoBuild':False,'enableBasicAuth':False}}]
    elif surface=='batch_environment':
        target['resource_id']=arn('batch','job-definition/'+name+':3')
        responses=[{'jobDefinitions':[{'jobDefinitionArn':target['resource_id'],'jobDefinitionName':name,'revision':3,'status':'ACTIVE','type':'container',
          'containerProperties':{'image':'public.ecr.aws/example/app:latest','environment':[{'name':'TOKEN' if positive else 'MODE','value':value}]}}]}]
    elif surface=='beanstalk_options':
        target['resource_id']=arn('elasticbeanstalk','environment/'+name+'/AuditEnvironment')
        responses=[{'ConfigurationSettings':[{'ApplicationName':name,'EnvironmentName':'AuditEnvironment','DeploymentStatus':'deployed',
          'Description':TOKEN,'OptionSettings':[{'Namespace':'aws:elasticbeanstalk:application:environment','OptionName':'TOKEN' if positive else 'MODE','Value':value}]}]}]
    elif surface=='glue_job_arguments':
        target['resource_id']=arn('glue','job/'+name)
        responses=[{'Job':{'Name':name,'Description':TOKEN,'DefaultArguments':{'--TOKEN' if positive else '--MODE':value},'NonOverridableArguments':{}}}]
    elif surface=='glue_connection_properties':
        target['resource_id']=arn('glue','connection/'+name)
        responses=[{'Connection':{'Name':name,'Description':TOKEN,'ConnectionType':'KAFKA',
          'ConnectionProperties':{'KAFKA_BOOTSTRAP_SERVERS':'broker.internal:9092','KAFKA_SSL_ENABLED':'true','USERNAME':value}}}]
    elif surface=='launch_template_userdata':
        target.update(resource_id=arn('ec2','launch-template/lt-0123456789abcdef0'),version=3)
        responses=[{'LaunchTemplateVersions':[{'LaunchTemplateId':'lt-0123456789abcdef0','VersionNumber':3,'DefaultVersion':False,
             'VersionDescription':TOKEN,'LaunchTemplateData':{'UserData':encoded(text)}}]}]
    elif surface=='launch_configuration_userdata':
        target['resource_id']=arn('autoscaling','launchConfiguration:11111111-1111-4111-8111-111111111111:launchConfigurationName/'+name)
        responses=[{'LaunchConfigurations':[{'LaunchConfigurationName':name,'LaunchConfigurationARN':target['resource_id'],
          'ImageId':'ami-0123456789abcdef0','InstanceType':'t3.micro','CreatedTime':NOW,'UserData':encoded(text)}]}]
    elif surface=='ssm_document':
        target.update(resource_id=arn('ssm','document/'+name),version=3)
        responses=[{'Document':{'Name':name,'DocumentVersion':'3','Owner':ACCOUNT,'Status':'Active','DocumentType':'Command','DocumentFormat':'JSON'}},
                   {'Name':name,'DocumentVersion':'3','Status':'Active','DocumentFormat':'JSON','DocumentType':'Command',
                    'Content':json.dumps({'schemaVersion':'2.2','mainSteps':[{'action':'aws:runShellScript','name':'test','inputs':{'runCommand':[text]}}]})}]
    elif surface=='state_machine_definition':
        target['resource_id']=arn('states','stateMachine:'+name)
        responses=[{'stateMachineArn':target['resource_id'],'name':name,'status':'ACTIVE','type':'STANDARD',
          'roleArn':arn('iam','role/unused'),'creationDate':NOW,
          'definition':json.dumps({'StartAt':'Review','States':{'Review':{'Type':'Pass','End':True,'Result':{'TOKEN' if positive else 'MODE':value}}}})}]
    elif surface=='notebook_lifecycle':
        target['resource_id']=arn('sagemaker','notebook-instance-lifecycle-config/'+name)
        responses=[{'NotebookInstanceLifecycleConfigName':name,'NotebookInstanceLifecycleConfigArn':target['resource_id'],
            'CreationTime':NOW,'LastModifiedTime':NOW,'OnCreate':[{'Content':encoded(text)}],'OnStart':[]}]
    else:
        target['resource_id']=arn('datapipeline','pipeline/df-0123456789ABC')
        responses=[{'pipelineObjects':[{'id':'ReviewTask','name':'ReviewTask','fields':[{'key':'type','stringValue':'ShellCommandActivity'},{'key':'command','stringValue':text}]}],
          'parameterObjects':[],'parameterValues':[]}]
    for response in responses:response['ResponseMetadata']=metadata()
    return target,responses
