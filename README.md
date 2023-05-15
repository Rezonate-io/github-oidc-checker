# github-oidc-checker
Tools that checks for misconfigured access to Github OIDC from AWS roles and GCP service accounts

## ABOUT

As part of their research on GitHub OIDC link to AWS & GCP, Rezonate Labs has created a scanning script. This script, released to the public, enables organizations to scan their accounts & projects identifying vulnerabilities in their IAM roles & service accounts.

## Usage

There are 2 scripts in this repository, both written in Python 3.11.
You should run them as an authenticated user and have the following dependencies installed:

**GCP:** gcloud cli (which can be downloaded from here https://cloud.google.com/sdk/docs/install ) 
**AWS:** boto3 python library (which can be installed by executing: pip install boto3)

## Execution Examples

**GCP**
![Example 1]([https://myoctocat.com/assets/images/base-octocat.svg](https://github.com/Rezonate-io/github-oidc-checker/blob/main/github-aws-example.png?raw=true))

**AWS**
![Example 1]([https://myoctocat.com/assets/images/base-octocat.svg](https://github.com/Rezonate-io/github-oidc-checker/blob/main/github-aws-example.png?raw=true))
