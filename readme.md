# AWS Access Analyser

This CloudFormation Template configures a Lambda Function that leverages parameters parsed into it via CloudFormation Parameter through the use of Environment Variables.  Specifically the Lambda Function does a number of things:
* Determines whether a Delegated Administrative Account exists for AWS Access Analyser.  If it doesn't then it enables Delegated Administration to the AWS Account ID that is parsed in.
* For Every Governed Region within AWS Control Tower, it then assumes the AWSControlTowerExecution Role into the Delegeated Administration Account and Creates an Analyser with an Organization Zone of Trust.
* For Every Active AWS Account within the Organisation, it then assumes the AWSControlTowerExecution Role into each Active AWS Account and Creates an Analyser with Account Zone of Trust.
* If the CloudFormation Stack is deleted, it removes the varying Analysers (both Organisation and Account Zone of Trusts) from every AWS Account and then deregisters the Delegated Administration.
* Since this Solution has been developed for use as an add-on for AWS Control Tower, Access Analyser Archive Rules have been created specifically for the purpose of reducing false positives highlighted by the AWSControlTowerExecution IAM Role and the IAM Roles that are created by AWS Single Sign-On as a result of the Permission Sets implemented.

The rationale behind this is for a number of reasons:
* The Organizational Zone of Trust provides visibility to a Single AWS Account (through Delegated Administration) the ability to have visibility of everything going on within the Organisation e.g. all IAM Roles, S3 Buckets.  However and this is just from what I've personally noticed is that it doesn't seem to have visibility of SQS Policies, KMS Key Policies, Lambda Functions, Lambda Layer Version or Secrets Manager Secrets.
* The Account Zone of Trust provides visibility into everything within the AWS Account including all the items that the Organization Zone of Trust seemed to be missing.
* S3 Access Analyser (within the S3 Service Console) is only available when there is an Account Zone of Trust configured.

## Architecture Overview

![alt](./diagrams/aws-access-analyser.png)

## Pre-Requisites and Installation

### Pre-Requisites

There is an overarching assumption that you already have [Customisation for Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) deployed within your Control Tower Environment.

1.  Clone the GitHub Repo to your local device.
2.  Create an S3 Bucket where you'll then upload the `access-analyser.zip` file to. Make a note of the bucket name and the prefix to the `access-analyser.zip`. Note: The region where you create the bucket will need to be in the region of the Control Tower home region since that is where the Lambda Function will be created.
3.  Create a prefix within the S3 Bucket named `lambda-layers` and upload `cfnresponse.zip`to that prefix.

### Installation

1.  Copy the CloudFormation Template `enable-access-analyser.yaml` should be added to the `/templates` folder for use with Customisations for Control Tower.
2.  Copy the CloudFormation Parameters `enable-access-analyser.json` should be added to `/parameters` folder for use with Customisations for Control Tower.
3.  Update the CloudFormation Parameters `enable-access-analyser.json` with the required details:
    * **OrganizationId:** This is used to implement conditions within the IAM Policy used for the Lambda Execution Role. This can be obtained from with AWS Organisations.
    * **AccessAnalyserMasterAccountId:** This is the AWS Account ID of the Account that you wish to configure as the delegated admin for Access Analyser.  It's recommended to use the Security Account (formerly called Audit Account) configured by Control Tower.
    * **S3SourceBucket:** This is the S3 Bucket where the Lambda Function source files are located. 
    * **S3Key:** This is the prefix within the S3 Bucket where the Lambda Function source files are located. 
    * **RoleToAssume:** This is used within the Lambda Function to AssumeRole into other AWS Accounts in order to Create/Configure/Delete different AWS Services such as Security Hub.  This is preconfigured with a default value of `AWSControlTowerExecution` since this IAM Role is created in all AWS Accounts as part the AWS Control Tower setup.

    The above values should be configured within the `enable-access-analyser.json`:

    ```json
    [
        {
            "ParameterKey": "OrganizationId",
            "ParameterValue": ""
        },
        {
            "ParameterKey": "AccessAnalyserMasterAccountId",
            "ParameterValue": ""
        },  
        {
            "ParameterKey": "S3SourceBucket",
            "ParameterValue": ""
        },
        {
            "ParameterKey": "S3Key",
            "ParameterValue": ""
        },
        {
            "ParameterKey": "RoleToAssume",
            "ParameterValue": "AWSControlTowerExecution"
        }
    ]
    ```

4.  Update the `manifest.yaml` and configure the `deployment_targets` and `regions` accordingly based on your needs. The deployment target should be the AWS Control Tower Management Account since the Lambda Function that is invoked uses API Calls that are run are only available to the Master Account whilst the region should be configured to the Control Tower home region.

    ```yaml 
    - name: Enable-AWS-Access-Analyser
      description: "CloudFormation Template to Enable AWS Access Analyser for the Organization"
      resource_file: templates/enable-access-analyser.yaml
      parameter_file: parameters/enable-access-analyser.json
      deploy_method: stack_set
      deployment_targets:
        accounts:
          - # Either the 12-digit Account ID or the Logical Name for the Control Tower Management Account
      regions:
        - # AWS Region that is configured as the Home Region within Control Tower
    ```