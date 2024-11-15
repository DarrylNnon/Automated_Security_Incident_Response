import boto3
import logging

ec2 = boto3.client('ec2')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    # Parse event to get instance ID
    instance_id = event['detail']['resource']['instanceDetails']['instanceId']
    logger.info(f"Isolating instance: {instance_id}")

    # Detach instance from all security groups and attach to quarantine group
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        security_groups = response['Reservations'][0]['Instances'][0]['SecurityGroups']

        # Remove all existing security groups
        ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[])

        # Attach to a quarantine security group (create one if not exists)
        quarantine_group = 'sg-12345678'  # Replace with actual quarantine group ID
        ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[quarantine_group])

        # Tag instance as quarantined
        ec2.create_tags(Resources=[instance_id], Tags=[{'Key': 'Quarantined', 'Value': 'True'}])

        logger.info(f"Instance {instance_id} successfully isolated.")
        return {"status": "Instance isolated"}
    except Exception as e:
        logger.error(f"Error isolating instance: {e}")
        return {"status": "Error", "details": str(e)}

