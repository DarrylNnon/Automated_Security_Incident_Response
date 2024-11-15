import boto3
import logging

ec2 = boto3.client('ec2')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    # Parse event to get the IP address
    suspicious_ip = event['detail']['service']['action']['networkConnectionAction']['remoteIpDetails']['ipAddressV4']
    logger.info(f"Blocking IP: {suspicious_ip}")

    try:
        # Update NACL rules to block the IP
        nacl_id = 'acl-12345678'  # Replace with your Network ACL ID
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=100,
            Protocol='-1',
            RuleAction='deny',
            Egress=False,
            CidrBlock=f"{suspicious_ip}/32"
        )
        logger.info(f"Successfully blocked IP: {suspicious_ip}")
        return {"status": "IP blocked"}
    except Exception as e:
        logger.error(f"Error blocking IP: {e}")
        return {"status": "Error", "details": str(e)}

