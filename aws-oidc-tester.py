import boto3
import json
from botocore.exceptions import NoCredentialsError

def check_vuln_sub_pattern(sub_patterns):
    if not isinstance(sub_patterns,list):
        sub_patterns = [sub_patterns]
    for pattern in sub_patterns:
        if pattern.index("*") > 0 and pattern.index("*") < pattern.index("/"):
            return True
    return False


def get_roles_paginated(client, **kwargs):
    """
    A generator function to handle pagination for AWS IAM APIs and return a list of roles.
    """
    paginator = client.get_paginator('list_roles')
    roles = []
    for page in paginator.paginate(**kwargs):
        for role in page['Roles']:
            roles.append(role)
    return roles


print("###########################")
print("Github OIDC Scanner - AWS")
print("By Rezonate.io")
print("###########################")
print("\nThis tool is not a replacement for an in-depth examination of permissions and service-accounts and its use is the sole responsibility of the user")
print()

try:
    print("Authenticating")
    iam_client = boto3.client('iam')
    print("Searching for OIDC Trust in the account")
    oidc_providers = iam_client.list_open_id_connect_providers()
    if len(oidc_providers) == 0:
        print("There are no trusted identity provider within the account.")
        exit(0)
    print("Checking if github is trusted")
    found_git = False        
    for provider in oidc_providers['OpenIDConnectProviderList']:
        if str(provider["Arn"]).endswith("token.actions.githubusercontent.com"):
            found_git = True
    if not found_git:
        print("GitHub OIDC trust was not detected.")
        exit(0)
    else:
        print("Found OIDC Trust for GitHub. searching for relevant roles")


except NoCredentialsError:
    print("Missing AWS credentials. please ensure that the script runs from authenticated terminal")
    exit(0)

roles = get_roles_paginated(iam_client)
github_roles = []
# iterate through the list of roles
for role in roles:
    if (not role["AssumeRolePolicyDocument"] or not role["AssumeRolePolicyDocument"]["Statement"]):
        continue
    statements = role["AssumeRolePolicyDocument"]["Statement"]
    if not isinstance(statements,list):
        statements = [statements]
    for statement in statements:
        if statement["Effect"] != "Allow":
            continue
        principals = statement["Principal"]
        if not isinstance(principals, list):
            principals = [principals]
        for principal in principals:
            if "Federated" in principal and str(principal["Federated"]).endswith("oidc-provider/token.actions.githubusercontent.com"):
                github_roles.append(role)

if len(github_roles) == 0:
    print("There are no roles that trusts GitHub OIDC")
    exit(0)

found_vuln = False
vuln_no_sub = []
vuln_loosy_sub = []

print(f"Found {len(github_roles)} roles that trusts GitHub OIDC. checking them")
for role in github_roles:
    print(f"Checking {role['RoleName']} , {role['Arn']}")
    statements = role["AssumeRolePolicyDocument"]["Statement"]
    for statement in statements:
        if statement["Effect"] != "Allow":
            continue
        if "Condition" not in statement or "token.actions.githubusercontent.com:sub" not in json.dumps(statement,default=str):
            vuln_no_sub.append(role)
            found_vuln = True
            continue
        condition = statement["Condition"]
        if "StringLike" in condition and "token.actions.githubusercontent.com:sub" in condition["StringLike"] and check_vuln_sub_pattern(condition["StringLike"]["token.actions.githubusercontent.com:sub"]):
            found_vuln = True
            vuln_loosy_sub.append(role)
            continue
            
        

if not found_vuln:
    print("\n-------------------------No Vulnerable roles detected.\n-------------------------")
    exit(0)

print("-------------------------\nFound Vulnerable roles!\n--------------------------")

if len(vuln_no_sub) > 0:
    print("Vulnerable Missing Subject:")
    for role in vuln_no_sub:
        print(f"[!]{role['Arn']}")


if len(vuln_loosy_sub) > 0:
    print("Vulnerable Bypassable Subject:")
    for role in vuln_loosy_sub:
        print(f"[!]{role['Arn']}")

        




