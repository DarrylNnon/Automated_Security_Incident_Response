import boto3
securityhub = boto3.client('securityhub')

def log_to_security_hub(description):
    response = securityhub.batch_import_findings(
        Findings=[
            {
                'Title': 'Automated Incident Response',
                'Description': description,
                'Resources': [{'Type': 'AWS::EC2::Instance', 'Id': instance_id}],
                'Severity': {'Label': 'MEDIUM'},
                'Types': ['Software and Configuration Checks'],
            },
        ]
    )

