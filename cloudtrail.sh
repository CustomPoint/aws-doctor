#!/usr/bin/env bash

FILTER_PATTERNS[0]='{($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'
FILTER_PATTERNS[1]='{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
FILTER_PATTERNS[2]='{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}'
FILTER_PATTERNS[3]='{($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging)}'
FILTER_PATTERNS[4]='{ ($.eventName = ConsoleLogin) && ($.errorMessage = "\"Failed authentication\"") }'
FILTER_PATTERNS[5]='{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion))}'
FILTER_PATTERNS[6]='{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }'
FILTER_PATTERNS[7]='{($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder))}'
FILTER_PATTERNS[8]='{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}'
FILTER_PATTERNS[9]='{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'
FILTER_PATTERNS[10]='{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
FILTER_PATTERNS[11]='{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'
FILTER_PATTERNS[12]='{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'


METRIC_NAMES=(
'UnauthorizedOperation'
'userIdentity'
'DeletePolicy'
'TrailChange'
'ConsoleLogin'
'ScheduleKeyDeletion'
'BucketPolicies'
'ConfigurationRecorder'
'SecurityGroup'
'NetworkAcl'
'InternetGateway'
'Route'
'VPC'
)

POLICIES=(
"3.1  Ensure a log metric filter and alarm exist for unauthorized API calls"
"3.3  Ensure a log metric filter and alarm exist for usage of root account (Scored)"
"3.4  Ensure a log metric filter and alarm exist for IAM policy changes (Scored)"
"3.5  Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)"
"3.6  Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)"
"3.7  Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)"
"3.8  Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)"
"3.9  Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)"
"3.10  Ensure a log metric filter and alarm exist for security group changes (Scored)"
"3.11  Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)"
"3.12  Ensure a log metric filter and alarm exist for changes to network gateways (Scored)"
"3.13  Ensure a log metric filter and alarm exist for route table changes (Scored)"
"3.14  Ensure a log metric filter and alarm exist for VPC changes (Scored)"
)

usage(){
  echo "
USAGE:
      `basename $0` -p <profile> -r <region> -L <log_group_name>
  Options:
      -p <profile>        specify your AWS profile to use (i.e.: default)
      -r <region>         specify an AWS region to direct API requests to (i.e.: us-east-1), all regions are checked anyway
      -L <log_group_name> specify an AWS CloudTrail Log Group that is working and is created appropriately
      -h                  this help
  "
  exit
}


while getopts ":hp:r:L:" OPTION; do
   case $OPTION in
     h )
        usage
        EXITCODE=1
        exit $EXITCODE
        ;;
     p )
        PROFILE=$OPTARG
        ;;
     r )
        REGION=$OPTARG
        ;;
     L )
        LOG_GROUP_NAME=$OPTARG
        ;;
     : )
        echo "ERROR!  -$OPTARG requires an argument"
        usage
        exit 1
        ;;
     ? )
        echo "ERROR! Invalid option"
        usage
        exit 1
        ;;
   esac
done

if [ "$OPTION" == '?' -a "$PROFILE" == '' ]; then
echo "ERROR! No parameters given."
usage
exit 1
fi



remediate(){
echo "Remediating : ${3}"
echo "With filter : ${2}"
# add log metric
RESULT=`aws logs describe-metric-filters --region ${REGION} --profile ${PROFILE}`
if [[ $RESULT =~ "$1" ]] ; then echo "= metric filter already exists: $1";
else
    aws logs put-metric-filter --region ${REGION} --profile ${PROFILE} --log-group-name ${LOG_GROUP_NAME}  --filter-name "${1}Filter" --metric-transformations metricName=${1},metricNamespace='CISBenchmark',metricValue=1 --filter-pattern "${2}"
    # check that everything went fine
    RESULT=`aws logs describe-metric-filters --region ${REGION} --profile ${PROFILE}`
    if [[ $RESULT =~ "$1" ]] ; then echo "= it went fine with logs for metric: $1"; fi
fi

RESULT=`aws cloudwatch describe-alarms --region ${REGION} --profile ${PROFILE}`
if [[ $RESULT =~ "${1}Alarm" ]] ; then echo "= alarm already exists: $1Alarm";
else
    # add cloudwatch alarm to metric
    aws cloudwatch put-metric-alarm --region ${REGION} --profile ${PROFILE} --alarm-name "${1}Alarm" --metric-name "${1}" --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark'
    RESULT=`aws cloudwatch describe-alarms --region ${REGION} --profile ${PROFILE}`
    if [[ $RESULT =~ "${1}Alarm" ]] ; then echo "= it went fine with alarm for metric: $1Alarm"; fi
fi
}


for ((i=0; i < ${#METRIC_NAMES[@]}; i++));
do
echo ""
remediate "${METRIC_NAMES[i]}" "${FILTER_PATTERNS[i]}" "${POLICIES[i]}"
done