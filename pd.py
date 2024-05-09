#!/usr/bin/python3

import argparse
import boto3
import digitalocean
import requests
import time
import random
import json
import socket
import logging
import re
import tldextract
import whois
import os
from dotenv import load_dotenv

# Args
parser = argparse.ArgumentParser()
parser.add_argument('--count', type=int, default=2, help='Number of IPs to catch and test.')
parser.add_argument('--log', nargs='?', type=str, default="pd.log", help='Log file for output. By default, this is ./pd.log. You must have write permissions to the specified file and enclosing directory. The enclosing directory[ies] must already exist.')
parser.add_argument('--cloud', type=str, choices=['aws', 'do'], default='aws', help='Cloud provider to be used Choices are AWS or Digital Ocean.')
args, _ = parser.parse_known_args()
parser.add_argument('--exclude', nargs='?', type=str, default=args.log, help='File containing IP addresses to exclude from lookup.')
args = parser.parse_args()

# Set up API Key from .env file
# Load environment variables from .env file
load_dotenv()

# Access the VT API key
VT_API_KEY = os.getenv('VT_API_KEY')
if not VT_API_KEY:
    print(f"Please set the VT_API_KEY in the .env file.")
    exit()

# Add excluded infrastructure domains here.
excluded_domains = {'amazonaws.com', 'elasticbeanstalk.com'}

ec2_client = None
ec2 = None
digital_ocean = None

# Initiate the correct cloud provider
if args.cloud == 'do':
    if not os.getenv('DO_API_KEY'):
        print(f"No Digital Ocean API Key available. Please set DO_API_KEY in .env file.")
        exit()
    do_manager = digitalocean.Manager(token=os.getenv('DO_API_KEY'))
# Default is AWS
else:
    ec2_client = boto3.client('ec2')
    ec2 = boto3.resource('ec2')

def get_domain_expiration_date(domain):
    domain_info = ''
    expiration_date = ''
    try:
        domain_info = whois.whois(domain)
    except:
        pass

    try:
        if domain_info.expiration_date:
            expiration_date =  domain_info.expiration_date.strftime('%Y-%m-%d')
    except:
        pass

    try:
        expiration_date = domain_info['expiration_date'][0]
        expiration_date = expiration_date.strftime('%Y-%m-%d')
    except:
        pass

    return expiration_date

def extract_domain(hostname):
    extracted = tldextract.extract(hostname)
    # Join the domain and suffix to get the full domain name
    domain = f"{extracted.domain}.{extracted.suffix}"
    return domain

def resolve_now(host_name, eip_string):
    #domain = extract_domain(host_name)
    try:
        current_ip = socket.gethostbyname(host_name)
    except:
        current_ip = '0.0.0.0'
        
    return current_ip

def allocate_and_release_ip(run_data):
    eip_string = ''
    chosen_region = ''

    if args.cloud == 'do':
        # We need extra sleep time to use the DO API
        time.sleep(20)
        url = 'https://api.digitalocean.com/v2/floating_ips'
        token = os.getenv('DO_API_KEY')
        # Set the headers, including the authorization header with your token
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        regions = [region for region in do_manager.get_all_regions() if region.available]

        chosen_region_do = random.choice(regions)
        run_data['region'] = chosen_region_do.name
        #print(f"Chosen Region: {run_data['region']}")

        # Allocate Floating IP

        # Set the payload to specify the region, without specifying a droplet_id
        payload = {
            'region': chosen_region_do.slug
        }

        # Make the POST request to create the Floating IP
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        if response.status_code == 202:
            data = response.json()
            print(f"Reserved IP Allocated: {data['floating_ip']['ip']} {run_data['region']}")
            run_data['ip_address'] = data['floating_ip']['ip']
        else:
            print(f"Failed to create Reserved IP: {response.content}")

        # Release Floating IP
        floating_ips = do_manager.get_all_floating_ips()
        for ip in floating_ips:
            if ip.ip == run_data['ip_address']:
                ip.destroy()
                print(f"Reserved IP Released: {run_data['ip_address']}")

    else:
        regions_response = ec2_client.describe_regions()
        regions = [region['RegionName'] for region in regions_response['Regions']]

        # Choose a region at random
        run_data['region'] = random.choice(regions)

        # Create an EC2 resource in the chosen region
        ec2 = boto3.resource('ec2', region_name=run_data['region'])

        # Allocate a new Elastic IP
        eip = ec2.meta.client.allocate_address(Domain='vpc')
        print(f"Elastic IP Allocated: {eip['PublicIp']} {run_data['region']}")
        run_data['ip_address'] = str(eip['PublicIp'])

        # Release the Elastic IP
        response = ec2.meta.client.release_address(AllocationId=eip['AllocationId'])
        print(f"Elastic IP Released: {run_data['ip_address']}")

    return run_data


def add_hostname_info(data, host_name):
    hostname_entry = {
        'hostname': host_name,
        'expiration_date': '',
        'is_match': False
    }
    data['host_names'].append(hostname_entry)
    return data

def extract_hostname(json_data, run_data):
    for item in json_data['data']:
        # Access the 'host_name' within each item's 'attributes'
        host_name = item['attributes']['host_name']

        run_data = add_hostname_info(run_data, host_name)
    
    return run_data

def passive_dns_lookup(run_data):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{run_data['ip_address']}/resolutions?limit=40"
    headers = {
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()

        run_data = extract_hostname(data, run_data)
        time.sleep(5)

    else:
        print("Failed to perform passive DNS lookup.")
        time.sleep(12)
    return run_data

def populate_addresses():
    tested_ips = set()
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    with open(args.exclude, 'r') as file:
        for line in file:
            # Find all instances of the pattern in the line
            found_ipv4_addresses = re.findall(ipv4_pattern, line)
        
            # Update the set with the found IPv4 addresses
            tested_ips.update(found_ipv4_addresses)
        file.close()
    return(tested_ips)

def check_quota():
    url = f"https://www.virustotal.com/api/v3/users/{VT_API_KEY}/overall_quotas"
    headers = {
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_data = response.json()

        # Calculate hourly remaining requests on API Key
        h_allowed = json_data['data']['api_requests_hourly']['user']['allowed']
        h_used = json_data['data']['api_requests_hourly']['user']['used']
        print(f"Hourly Remaining Requests:\t{h_allowed-h_used}")

        # Calculate Daily remaining requests on API Key
        d_allowed = json_data['data']['api_requests_daily']['user']['allowed']
        d_used = json_data['data']['api_requests_daily']['user']['used']
        print(f"Daily Remaining Requests:\t{d_allowed-d_used}")

        # Adjust args.count if daily remaining requests on API Key
        if d_allowed-d_used < args.count:
            print(f"Number of IPs to catch and test has been adjusted from {args.count} to {max(d_allowed-d_used, 0)}")
            args.count = max(d_allowed-d_used, 0)

    elif response.status_code == 429:
        print("Quota exceeded on this API key or source IP address.")
        args.count = 0
    else:
        print(response)
        print("Unable to get Virus Total API Key usage data.\nThis is indictive of 0 remaining requests on your API key or an outage.")

def get_empty_data_struct():
    data = {
        'ip_address': None,
        'host_names': [],
        'runs_remaining': args.count,
        'region': None,  
        'cloud': args.cloud
    }
    return data

def main():
    # Set up logger
    logging.basicConfig(filename=args.log, level=logging.INFO, format='%(asctime)s|%(message)s')
    ip_count = 0
    tested_ips = populate_addresses()
    num_addr = len(tested_ips)
    print("\nWelcome to Pay Dirt! We will help you find golden IP address \nnuggets in the masses. Below is a summary of this run:\n")
    print("===================================")
    print(f"Number of IPs already checked: {num_addr}")
    check_quota()
    print("===================================")

    while ip_count < args.count:
        run_data = get_empty_data_struct()

        # Fetch an IP address to potentially test
        run_data = allocate_and_release_ip(run_data)

        # If IP address has not been seen before, continue to investigate
        if run_data['ip_address'] not in tested_ips:
            logging.info(f"{run_data['ip_address']}||{run_data['cloud']}|{run_data['region']}|")
            run_data = passive_dns_lookup(run_data)

            # If Passive DNS returns hostnames, continue to resolve now
            if run_data['host_names']:
                for entry in run_data['host_names']:
                    current_ip = resolve_now(entry['hostname'], run_data['ip_address'])
                    if current_ip == run_data['ip_address'] and extract_domain(entry['hostname']) not in excluded_domains:
                        entry['is_match'] = True
                        entry['expiration_date'] = get_domain_expiration_date(extract_domain(entry['hostname']))
                        logging.info(f"{run_data['ip_address']}|{entry['hostname']}|{run_data['cloud']}|{run_data['region']}|{entry['expiration_date']}|MATCH")

            tested_ips.add(run_data['ip_address'])
            ip_count = ip_count + 1
            #print(run_data)
        #else:
        #    tested_ips.add(run_data['ip_address'])

if __name__ == "__main__":
    main()
        
