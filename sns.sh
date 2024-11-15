sns = boto3.client('sns')
sns.publish(
    TopicArn='arn:aws:sns:region:account-id:SecurityAlerts',
    Message="Suspicious activity detected. Automated action has been taken.",
    Subject="Security Incident Alert"
)

