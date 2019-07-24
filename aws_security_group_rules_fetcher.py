#!/usr/bin/env python
# authors: bagopila@gmail.com, sudhinmachad@gmail.com, nagarajanselvaraj92@gmail.com
import boto3
import json

ec2 = boto3.resource('ec2')
instances = ec2.instances.filter()
instances_meta = []

for instance in instances:
    instance_id = instance.id
    instance_name = ""
    for tag in instance.tags:
        if tag['Key'] == 'Name':
            instance_name = tag['Value']
    all_sg_ids = [sg['GroupId'] for sg in instance.security_groups]
    
    
    for sg_id in all_sg_ids:
        sg = ec2.SecurityGroup(sg_id)
        ingressRules = sg.ip_permissions # list of rules
        # ingress rule can also point to another security group as well
        egressRules = sg.ip_permissions_egress
        
        rules_length = len(ingressRules) if len(ingressRules) > len(egressRules) else len(egressRules)
        for i in range(rules_length):
            instance_meta = {}
            instance_meta["instance_id"] = instance_id
            instance_meta["instance_name"] = instance_name
            instance_meta["security_group_id"] = sg_id
            
            if i <= len(ingressRules)-1 and ingressRules:
                ip_ranges = ""
                for ip_range in ingressRules[i]['IpRanges']:
                    ip_ranges += ip_range['CidrIp'] + ","
                    
                user_group_pairs = ingressRules[i]['UserIdGroupPairs']
                sub_security_group = user_group_pairs[0]['GroupId'] if user_group_pairs else ""
                    
                instance_meta["ingress_CIDR_IP"] = "[" + ip_ranges + "]"
                instance_meta["ingress_protocol"] = ingressRules[i]['IpProtocol']
                if 'FromPort' in ingressRules[i]:
                    instance_meta["ingress_FromPort"] = ingressRules[i]['FromPort']
                else:
                    instance_meta["ingress_FromPort"] = ""                
                if 'ToPort' in ingressRules[i]:
                    instance_meta["ingress_ToPort"] = ingressRules[i]['ToPort']
                else:
                    instance_meta["ingress_ToPort"] = ""                    
                instance_meta["ingress_sub_security_group"] = sub_security_group                
            else:
                instance_meta["ingress_CIDR_IP"] = ""
                instance_meta["ingress_protocol"] = ""
                instance_meta["ingress_FromPort"] = ""
                instance_meta["ingress_ToPort"] = ""
                instance_meta["ingress_sub_security_group"] = ""
                
            if i <= len(egressRules)-1 and egressRules:
                ip_ranges = ""
                for ip_range in egressRules[i]['IpRanges']:
                    ip_ranges += ip_range['CidrIp'] + ","
                                    
                instance_meta["egress_CIDR_IP"] = "[" + ip_ranges + "]"
                instance_meta["egress_protocol"] = egressRules[i]['IpProtocol']
            else:
                instance_meta["egress_CIDR_IP"] = ""
                instance_meta["egress_protocol"] = ""
                
            instances_meta.append(instance_meta)

with open('security_groups.json', 'w') as outfile:
    json.dump(instances_meta, outfile)
