# Automated Security Incident Response
Setting up an Automated Security Incident Response system is a critical project in DevSecOps, enabling faster responses to security incidents, reducing manual intervention, and ensuring consistent handling of threats.
This guide will walk me through setting up an automated response system using AWS Lambda functions for triggering alerts, isolating compromised resources, logging incidents, and integrating with SIEM system.

I will demonstrate with AWS as an example platform, but similar steps apply in Azure with Azure Functions.

Setting up an **Automated Security Incident Response** system is a critical project in DevSecOps, enabling faster responses to security incidents, reducing manual intervention, and ensuring consistent handling of threats. This guide will walk you through setting up an automated response system using AWS Lambda functions for triggering alerts, isolating compromised resources, logging incidents, and integrating with a SIEM system. 

I’ll demonstrate with AWS as an example platform, but similar steps apply in Azure with Azure Functions.


## Project Overview: Automated Security Incident Response in AWS

In this project, we’ll:
1. **Set up AWS Lambda functions** to trigger alerts and take action on security events.
2. **Configure automated responses**, such as isolating compromised resources.
3. **Integrate with a SIEM system** for centralized incident logging and alerting.
4. **Document the incident response procedures** for consistency and team training.

### Prerequisites
1. **AWS Account** with appropriate permissions.
2. **Basic AWS Lambda and IAM Knowledge**: Familiarity with AWS Lambda functions, IAM policies, and Security Hub.
3. **SIEM System Setup**: Have a SIEM system like AWS Security Hub, Splunk, or an equivalent ready for integration.
4. **Python Knowledge**: For creating Lambda functions, as most examples will use Python code.


### Step 1: Set Up AWS Lambda Functions to Trigger Alerts

We’ll start by creating an AWS Lambda function to respond to specific security events, such as unauthorized access attempts or detection of compromised resources.

#### Step 1.1: Create the Lambda Function

**Example Function**: Isolate a compromised EC2 instance if an unauthorized access attempt is detected.

1. **Navigate to Lambda Console**:
   - Go to **AWS Management Console** > **Lambda** > **Create function**.
   - Select **Author from scratch**, name the function (e.g., `IsolateCompromisedInstance`), and choose **Python 3.x** as the runtime.

2. **Set up Execution Role**:
   - Create a new role with basic Lambda permissions and add **EC2 permissions** to allow the function to take action on EC2 instances.
   - Attach the following permissions to the Lambda’s execution role:
     - `ec2:DescribeInstances`
     - `ec2:ModifyInstanceAttribute`
     - `ec2:CreateTags`

3. **Lambda Function Code**:
   - Here’s an example script to isolate an EC2 instance by removing it from its security groups.

   ```python
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
   ```

4. **Configure Event Trigger**:
   - Add an **EventBridge (CloudWatch Events)** trigger:
     - Go to the **Add trigger** section, select **EventBridge**.
     - Set up a rule to trigger the function when a suspicious activity is detected (e.g., from AWS Security Hub or GuardDuty).

5. **Test the Function**:
   - Create a test event that simulates an unauthorized access incident on an EC2 instance.
   - Test the Lambda function and confirm that it isolates the instance by changing its security group to a quarantine group.

### Step 2: Configure Automated Responses (e.g., Isolating Compromised Resources)

This step involves configuring response actions for various incident types, such as blocking IPs, suspending user accounts, or isolating instances.

#### Step 2.1: Example: Automatically Block Suspicious IPs Using Lambda and VPC Network ACLs

**Lambda Function Code**: This function adds an IP to a deny list on a VPC’s Network ACL to block traffic from a suspicious IP.

```python
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


- **Trigger**: Set up an EventBridge rule to trigger on GuardDuty findings related to suspicious IP addresses.


### Step 3: Integrate Incident Logging and Alerting into a SIEM System

Integrate the automated responses and security findings into a SIEM system for centralized monitoring.

#### Step 3.1: Send Incident Data to Security Hub or a Third-Party SIEM

1. **Security Hub Integration**:
   - Ensure **AWS Security Hub** is enabled.
   - In the Lambda function, log any actions taken and findings to Security Hub by using the `securityhub` Boto3 client.

   ```python
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

2. **Send Alerts to SNS** (Simple Notification Service):
   - To notify the security team, configure an SNS topic.
   - Add an SNS notification action in each Lambda function, or use CloudWatch to trigger notifications on critical events.

   ```python
   sns = boto3.client('sns')
   sns.publish(
       TopicArn='arn:aws:sns:region:account-id:SecurityAlerts',
       Message="Suspicious activity detected. Automated action has been taken.",
       Subject="Security Incident Alert"
   )
   ```

### Step 4: Document Response Procedures

Documentation is crucial for consistency and team training. Create a document that outlines each automated response, triggers, and steps taken in an incident.

#### **Automated Security Incident Response Documentation Template**

**1. Overview**  
This document details automated responses for common security incidents, including unauthorized access and compromised resources.

**2. Incident Response Procedures**  

- **Unauthorized Access Detected on EC2 Instance**:
  - **Trigger**: AWS Security Hub or GuardDuty finding for unauthorized access.
  - **Automated Response**: The Lambda function isolates the instance by removing it from its security groups and adding it to a quarantine group.
  - **Notification**: Sends an alert to the SNS topic, notifying the security team.

- **Suspicious IP Detected**:
  - **Trigger**: AWS GuardDuty finding for a suspicious IP address.
  - **Automated Response**: The Lambda function blocks the IP using a Network ACL.
  - **Notification**: Sends an alert to SNS and logs the incident in Security Hub.

**3. Integration with SIEM**  
- All incidents and automated responses are logged to AWS Security Hub, which integrates with our SIEM solution for centralized monitoring.

**4. Review and Update**  
- These procedures are reviewed quarterly to adjust responses based on evolving threat intelligence.

---

### Summary of Implementation Steps

1. **Lambda Functions for Incident Response**: Created Lambda functions to handle incidents like instance isolation and IP blocking.
2. **Automated Responses**: Configured response actions to quarantine instances and block IPs.
3. **SIEM Integration**: Integrated with Security Hub and SNS for centralized logging and alerting.
4. **Documentation**: Documented response procedures for each automated incident type.

---

### Testing and Deployment

1. **Test Each Lambda Function**: Use mock events to simulate incidents.
2. **Monitor Logs**: Use CloudWatch logs to verify that each response and alert is functioning as expected.
3. **Schedule Regular Reviews**: Regularly review automated responses to ensure they
