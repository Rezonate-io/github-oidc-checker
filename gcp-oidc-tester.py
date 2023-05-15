import subprocess
import json

identity_pools_paths = []
vuln_services = []
github_services = []

def get_identity_pools(project_id):
    command = f"gcloud iam workload-identity-pools list --location=global --project={project_id} --format=json"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    identity_pools = []
    if stdout:
        identity_pools = stdout.decode().strip()
    else:
        print("Error while listing pools")
        exit(0)
    return identity_pools

def get_service_accounts(project_id):
    command = f"gcloud iam service-accounts list --project={project_id} --format=json"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    service_accounts = []
    if stdout:
        service_accounts = stdout.decode().strip()
    else:
        print("Error while listing service accounts")
        exit(0)
    return service_accounts

def get_binding(service_account_email,project_id):
    command = f"gcloud iam service-accounts get-iam-policy --project={project_id} {service_account_email} --format=json"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if stdout:
        info = stdout.decode().strip()
        return info
    print("Error while getting service accounts bindings info")
    exit(0)
    



def get_identity_pool_info(project_id,identity_pool):
    command = f"gcloud iam workload-identity-pools providers list --project={project_id} --location=global --workload-identity-pool={identity_pool} --format=json"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if stdout:
        info = stdout.decode().strip()
        return info
    print("Error while getting pool info")
    exit(0)

def main():
    project_id = input("Enter the Project ID: ")
    print("Checking Identity Pools")
    identity_pools = get_identity_pools(project_id)
    print("Checking Service Accounts")
    service_accounts =  get_service_accounts(project_id)

    if identity_pools:
        pools = json.loads(identity_pools)
        for pool in pools:
            if pool["state"] != "ACTIVE":
                continue
            pool_providers_info = get_identity_pool_info(project_id,pool["name"])
            pool_providers_info = json.loads(pool_providers_info)
            for provider in pool_providers_info:
                if "oidc" in provider and str(provider["oidc"]["issuerUri"]).lower() == "https://token.actions.githubusercontent.com":
                    if (pool["name"] not in identity_pools_paths):
                        identity_pools_paths.append(pool["name"])

    else:
        print(f"No identity pools found in project '{project_id}'.")
        print("Scan completed, no possible vuln service accounts were found")
        exit(0)
    
    if service_accounts:
        service_accounts = json.loads(service_accounts)
        for svc in service_accounts:
            if svc["disabled"] != False:
                continue      
            binding = get_binding(svc['email'],project_id)
            if binding:
                binding_parsed = json.loads(binding)
                if "bindings" in binding_parsed:
                    members = binding_parsed["bindings"]
                    if not isinstance(members,list):
                        members = [members]
                    for member_binding in members:
                        for member_binding_pool_rule in member_binding["members"]:
                            rule = str(member_binding_pool_rule)
                            rule = member_binding_pool_rule.replace("principalSet://iam.googleapis.com/","").replace("principal://iam.googleapis.com/","")
                        for idp in identity_pools_paths:
                            if idp in rule:
                                if not svc["email"] in github_services:
                                    github_services.append(svc["email"])
                                rule = rule.replace(idp,"")
                        if rule == "/*":
                            vuln_services.append(svc['email'])
    print("\n-------------------------------\nScan results\n-------------------------------")
    print(f"Found {len(identity_pools_paths)} GitHub Identity Providers")
    for idp in identity_pools_paths:
        print(f"[*]{idp}")
    print()
    print(f"\nFound {len(github_services)} Service accounts with access to GitHub identity provider")
    for git in github_services:
        print(f"[*]{git}")
    print()
    if vuln_services:
        print(f"Found Possibly Vulnerable Service Accounts:")
        for vuln in vuln_services:
            print(f"[!]{vuln}")
    else:
        print("Did not find any possibly Vulnerable Service Accounts")

if __name__ == "__main__":
    print("###########################")
    print("Github OIDC Scanner - GCP")
    print("By Rezonate.io")
    print("###########################")
    print("\nThis tool is not a replacement for an in-depth examination of permissions and service-accounts and its use is the sole responsibility of the user")
    print()
    main()