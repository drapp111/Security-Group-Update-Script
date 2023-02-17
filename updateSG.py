# Tags which identify the security groups you want to update
# For a security group to be updated it will need to be tagged as 'auto-update: true'
# For an ingress rule to be updated, the description will need to be set as 'Automatic Update'

SG_TAGS = {'auto-update': 'true' }

#Imports

import boto3
import logging
import urllib.request, urllib.error, urllib.parse
import os

#Runs the update

def run():
    # Set up logging
    logging.getLogger().setLevel(logging.ERROR)
    # Set the environment variable DEBUG to 'true' if you want verbose debug details in CloudWatch Logs.
    try:
        if os.environ['DEBUG'] == 'true':
            logging.getLogger().setLevel(logging.INFO)
    except KeyError:
        pass

    #Create list of current IP CIDRs based on public IP from ident.me and AWS public IP from checkip.amazonaws.com
    updated_ips = retrieve_ips()
    
    # Update the security groups
    result = update_security_groups(updated_ips)
    
    print(result)

#Retrieves IPs from ident.me and checkip.amazonaws.com and formats them as a list to use for updating security groups
    
def retrieve_ips():
    
    #Retrive public IP from checkip.amazonaws.com, strip excess characters (i.e. \n), and add the CIDR range
    check_ip = urllib.request.urlopen('http://checkip.amazonaws.com/').read().decode('utf8').strip() + '/32'
    
    #Retrieve public IP from ident.me, strip excess characters (i.e. \n), and add the CIDR range
    public_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8').strip() + '/32'

    #Return list of IPs
    return [public_ip, check_ip]

#Updates the security groups that meet the tagging criteria ('auto-update': true)

def update_security_groups(new_ranges):

    #Create the client
    client = boto3.client('ec2')
    #Final result list
    result = list()
    #Local variable for defining tag criteria
    tagToFind = SG_TAGS
    #Security groups to update based on tags
    rangeToUpdate = get_security_groups_for_update(client, tagToFind)

    #If security groups to update are found, update grouips appropriately
    if len(rangeToUpdate) != 0:
        for securityGroupToUpdate in rangeToUpdate:
            if update_security_group(client, securityGroupToUpdate, new_ranges):
                result.append('Security Group {} updated.'.format( securityGroupToUpdate['GroupId'] ) )
            else:
                result.append('Security Group {} unchanged.'.format( securityGroupToUpdate['GroupId'] ) )

    return result

#Updates individual security groups

def update_security_group(client, group, new_ranges):
    #Identifies rules that are added and removed
    added = 0
    removed = 0

    #If IP permission rules exist, revoke current rules with 'Automatic Update' description and create new rules based on IPs that were retrieved
    if len(group['IpPermissions']) > 0:
        for permission in group['IpPermissions']:
            old_prefixes = list()
            to_revoke = list()
            to_add = list()
            add_rules = False
            #Remove all rules with description 'Automatic Update'
            for range in permission['IpRanges']:
                if 'Description' in range:
                    if range['Description'] == 'Automatic Update':
                        to_revoke.append(range)
                        #Set add_rules to true since Automatic Update rules were removed from this group
                        add_rules = True
            #If Automatic Update rules were removed, replace them with the new rules
            if add_rules:
                for range in new_ranges:
                    to_add.append({ 'CidrIp': range, 'Description': 'Automatic Update' })
            #Perform the permission revoke
            removed += revoke_permissions(client, group, permission, to_revoke)
            #Add the new rules after permissions are revoked to avoid overlap
            added += add_permissions(client, group, permission, to_add)
    #If the group has no rules, just add the new ones and default to allow all access
    else:
        to_add = list()
        for range in new_ranges:
            to_add.append({ 'CidrIp': range, 'Description': 'Automatic Update' })
        permission = {'IpProtocol': '-1'}
        added += add_permissions(client, group, permission, to_add)
    
    #Return true if rules were removed or added
    return (added > 0 or removed > 0)

#Revokes the old permissions to allow new permissions to be added without overlap

def revoke_permissions(client, group, permission, to_revoke):
    #If there are rules to revoke
    if len(to_revoke) > 0:
        #If the rule has a specific port, sets parameters accordingly
        if 'FromPort' in permission and 'ToPort' in permission: 
            revoke_params = {
                'ToPort': permission['ToPort'],
                'FromPort': permission['FromPort'],
                'IpRanges': to_revoke,
                'IpProtocol': permission['IpProtocol']
            }
        #If the rule allows all access, sets parameters accordingly
        else:
            revoke_params = {
                'IpRanges': to_revoke,
                'IpProtocol': permission['IpProtocol']
            }
        #Revoke old rule
        client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[revoke_params])
    #Return length of revoked rules
    return len(to_revoke)

#Adds the new permissions to the security group

def add_permissions(client, group, permission, to_add):
    #If there are new rules to add
    if len(to_add) > 0:
        #If the rule allows access to a specific port, this sets parameters to allow access to that same port as was previously configured, but with new IP
        if 'FromPort' in permission and 'ToPort' in permission: 
            add_params = {
                'ToPort': permission['ToPort'],
                'FromPort': permission['FromPort'],
                'IpRanges': to_add,
                'IpProtocol': permission['IpProtocol']
            }
        #If the rule allows all access, keeps configuration and updates IP
        else:
             add_params = {
                'IpRanges': to_add,
                'IpProtocol': permission['IpProtocol']
            }
        #Add the rule
        client.authorize_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[add_params])
    #Return length of added rules
    return len(to_add)

#Retrieves the security groups that meet the tagging criteria

def get_security_groups_for_update(client, security_group_tag):
    filters = list()
    #Filter based on tag values defined above
    for key, value in security_group_tag.items():
        filters.extend(
            [
                { 'Name': "tag-key", 'Values': [ key ] },
                { 'Name': "tag-value", 'Values': [ value ] }
            ]
        )
    #Retrieve matching groups
    response = client.describe_security_groups(Filters=filters)
    #Return relevant group data
    return response['SecurityGroups']

#Runs the program, added for scheduled runs and ease of use
run()
