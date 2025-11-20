import os.path

from netaddr.ip import IPAddress, IPNetwork

import UIToolsP3

import mistapi
import netaddr

import json
import getopt
import sys
import copy

env_file = "~/.mist_env"
conf_file = None
org_id = None

def read_junos_apps(conf_file):
    '''
    :param conf_file:
    :return: apps in the form of:
    apps = {
        '<Name>': {
            'protocol' = 'protocol'
            'destination-port' = 'port'
        }
        '<Group_Name>' = [
            {
                'protocol' = 'protocol'
                'destination-port' = 'port'
            }
        ]
    }
    '''
    apps = {}
    ofile = open(conf_file, 'r')
    for line in ofile:
        delimit = line.split(" ")
        if len(delimit) >= 5:
            if delimit[1] == "applications":
                if delimit[2] == "application":
                    app_name = delimit[3]
                    if app_name not in apps: apps[app_name] = {}
                    apps[app_name][delimit[4]] = delimit[5].strip()
                elif delimit[2] == "application-set":
                    app_set_name = delimit[3]
                    app_name = delimit[5].strip()
                    if app_name not in apps: print("Error: Can't find address "+app_name+" for address set "+app_set_name)
                    if app_set_name not in apps:
                        apps[app_set_name] = [apps[app_name]]
                    else:
                        apps[app_set_name].append(apps[app_name])
    return apps

def read_junos_addresses(conf_file):
    '''
    :param conf_file:
    :return: dictionary of addresses in the form of:
    adds = {
        '<Name>': [list of adds]
    }
    '''
    ofile = open(conf_file, 'r')

    addresses = {}
    raw_address_sets = []
    for line in ofile:
        if line.startswith("set security address-book"):
            delimit = line.split(" ")
            if delimit[4] == "address-set":
                raw_address_sets.append(line)
            else:
                address_name = delimit[5]
                address_ip = delimit[6].strip()
                addresses[address_name] = [address_ip]

    for line in raw_address_sets:
        delimit = line.split(" ")
        set_name = delimit[5]
        add_name = delimit[7].strip()
        if add_name in addresses:
            add_ip = addresses[add_name]
        else:
            print("Error: Can't find address "+add_name+" for address set "+set_name)
            continue

        if set_name in addresses:
            for ip in add_ip:
                addresses[set_name].append(ip)
        else:
            for ip in add_ip:
                addresses[set_name] = [ip]

    return addresses

def read_junos_policies(conf_file):
    '''
    :param conf_file:
    :return: policy dict in form of:
    policies_dict: {
        'fromzone-tozone': {
            'FromZone': zone,
            'ToZone': zone,
            'Policies': {
                'policy': {
                    'Application': {
                        'source-address': [addresses]
                        'destination-address': [addresses]
                        'application': [applications]
                    }
                    'Action': action
                }
            }
        }
    }
    '''
    ofile = open(conf_file, 'r')

    policies_dict = {}
    cur_match_set = {}
    for line in ofile:
        if line.startswith("set security policies from-zone"):
            delimit = line.split(" ")
            from_zone = delimit[4]
            to_zone = delimit[6]
            policy_name = delimit[8]
            if delimit[9] == "match":
                match_type = delimit[10]
                match_criteria = delimit[11].strip()
                if match_type in cur_match_set:
                    cur_match_set[match_type].append(match_criteria)
                else:
                    cur_match_set[match_type] = [match_criteria]
            elif delimit[9] == "then":
                policy_action = delimit[10].strip()
                if policy_action == 'permit' or policy_action == 'deny':
                    #print(policy_action)
                    zone_name = from_zone + '-' + to_zone
                    name_dadd = cur_match_set["destination-address"] if type(cur_match_set["destination-address"]) is not list else cur_match_set["destination-address"][0]
                    name_app = cur_match_set["application"] if type(cur_match_set["application"]) is not list else cur_match_set["application"][0]
                    application_name = name_dadd+'-'+name_app
                    if zone_name not in policies_dict: policies_dict[zone_name] = {}
                    policies_dict[zone_name]['FromZone'] = from_zone
                    policies_dict[zone_name]['ToZone'] = to_zone
                    app_dict = {
                        'app_name': application_name,
                        'match_set': cur_match_set
                    }
                    if "Policies" not in policies_dict[zone_name]:
                        policies_dict[zone_name]["Policies"] = {}
                    policies_dict[zone_name]["Policies"][policy_name] = {'Application': app_dict, 'Action': policy_action}
                    cur_match_set = {}

    return policies_dict

def read_junos_zones(conf_file):
    '''
        :param conf_file:
        :return: zone dict in form of:
        zones_dict: {
            'ZONE': {
                'interfaces': [],
                'host-inbound-traffic': []
            }
        }
    '''
    ofile = open(conf_file, 'r')

    zone_dict = {}
    for line in ofile:
        if line.startswith("set security zones security-zone"):
            delimit = line.split(" ")
            zone = delimit[4].strip()
            if zone not in zone_dict: zone_dict[zone] = {'interfaces': [], 'host-inbound-traffic': []}
            if delimit[5] == "interfaces":
                interface = delimit[6].strip()
                if interface not in zone_dict[zone]['interfaces']: zone_dict[zone]['interfaces'].append(interface)
                if len(delimit) > 7: #not just listing the interface
                    if delimit[7] == 'host-inbound-traffic':
                        #This would mean host-inbound-traffic per interface in zone
                        pass
            elif delimit[5] == 'host-inbound-traffic':
                hit = delimit[6].strip() + ' ' + delimit[7].strip()
                if hit not in zone_dict[zone]['host-inbound-traffic']: zone_dict[zone]['host-inbound-traffic'].append(hit)
    return zone_dict

def read_junos_interfaces(conf_file):
    '''
        :param conf_file:
        :return: interface dict in form of:
        interface_dict: {
            'INTERFACE': {
                'description': '',
                'units': {
                    'UNIT': {
                        'description': '',
                        'family': '',
                        'address': '',
                        'interface mode': '',
                        'vlan members': ''
                    }
                }
            }
        }
    '''
    ofile = open(conf_file, 'r')

    #TODO Add vlan lookup to connect IRBs

    interface_dict = {}
    for line in ofile:
        line = line.strip()
        if line.startswith('set interfaces'):
            delimit = line.split(' ')
            interface = delimit[2]
            if interface not in interface_dict:
                interface_dict[interface] = {
                    'description': '',
                    'units': {}
                }
            if delimit[3] == 'description':
                description = ' '.join(delimit[4:])
                interface_dict[interface]['description'] = description
            elif delimit[3] == 'unit':
                unit = delimit[4]
                if unit not in interface_dict[interface]['units']:
                    interface_dict[interface]['units'][unit] = {
                        'description': '',
                        'family': '',
                        'address': '',
                        'interface mode': '',
                        'vlan members': []
                    }
                if delimit[5] == 'description':
                    interface_dict[interface]['units'][unit]['description'] = ' '.join(delimit[6:])
                elif delimit[5] == 'family':
                    family = delimit[6]
                    interface_dict[interface]['units'][unit]['family'] = family
                    if delimit[7] == 'address':
                        address = delimit[8]
                        interface_dict[interface]['units'][unit]['address'] = address
                    elif delimit[7] == 'vlan':
                        vlans = delimit[9:]
                        interface_dict[interface]['units'][unit]['vlan members'] = vlans
                    elif delimit[7] == 'interface-mode':
                        interface_mode = delimit[8]
                        interface_dict[interface]['units'][unit]['interface mode'] = interface_mode

    return interface_dict

def app_lookup(names, junos_apps, problem_cases):
    '''
    :param names: application names to lookup
    :param junos_apps: applications from conf file
    :param problem_cases: working list of failed cases
    :return: built out application in form of:
    app = [
        {
            'protocol': 'protocol',
            'port_range': 'port_range'
        }
    ]
    '''

    junos_app_defs = {}
    try:
        with open('JunosAppDefinitions.json', 'r') as jf:
            junos_app_defs = json.load(jf)
    except FileNotFoundError:
        print('Could not find Junos App Definitions JSON file. If there are any Junos apps, they will be skipped')

    ans = []
    for name in names:
        if name in junos_app_defs:
            ans.append(junos_app_defs[name])
        elif name in junos_apps:
            if type(junos_apps[name]) is list:
                for sub_app in junos_apps[name]:
                    ans.append({"protocol": sub_app["protocol"],
                             "port_range": sub_app["destination-port"]})
            else:
                ans.append({"protocol": junos_apps[name]["protocol"], "port_range": junos_apps[name]["destination-port"]})
        else:
            print("Could not find application for " + name)
            problem_cases.append("Application: "+name)

    #Mist seems to want single port apps to be "22-22" not just "22"
    #Not totally sure if required, better safe then sorry
    for app in ans:
        if "port_range" in app:
            if "-" not in app["port_range"]:
                app["port_range"] = app["port_range"]+"-"+app["port_range"]
    return ans

def ingest_SRX():
    UIToolsP3.printSubHeader('From SRX')
    print('Please provide the path the to SRX config file (needs to be in set format)')
    conf_file = UIToolsP3.getFile()

    problem_cases = []

    # Mist objects often require broader context than Junos, so we gather all the junos data first, then build Mist Objs
    junos_apps = read_junos_apps(conf_file)
    with open('junos_apps.json', 'w+') as of:
        of.write(json.dumps(junos_apps, indent=4))

    junos_adds = read_junos_addresses(conf_file)
    with open('junos_adds.json', 'w+') as of:
        of.write(json.dumps(junos_adds, indent=4))

    junos_policies = read_junos_policies(conf_file)
    with open('junos_policies.json', 'w+') as of:
        of.write(json.dumps(junos_policies, indent=4))

    junos_zones = read_junos_zones(conf_file)
    with open('junos_zones.json', 'w+') as of:
        of.write(json.dumps(junos_zones, indent=4))

    junos_interfaces = read_junos_interfaces(conf_file)
    with open('junos_interfaces.json', 'w+') as of:
        of.write(json.dumps(junos_interfaces, indent=4))

    #Build Mist Objects
    mist_apps = {}
    organized_nets = {}
    mist_policies = {}
    for fztz in junos_policies.values():
        for policy_name, policy in fztz["Policies"].items():

            #For Each Junos Policy


            #Build Mist App
            mist_services = []
            dapp_obj = policy['Application']['match_set']
            mist_app = {"name": policy['Application']['app_name'],
                        "description": 'Original Policy Name: '+policy_name,
                        "type": "custom",
                        "traffic_type": "default",
                        "specs": app_lookup(dapp_obj["application"], junos_apps, problem_cases)}

            m_dadd = []
            for dadd in dapp_obj["destination-address"]:
                if dadd in junos_adds:
                    for result in junos_adds[dadd]:
                        m_dadd.append(result)
                elif dadd == "any":
                    m_dadd.append("0.0.0.0/0")
                else:
                    problem_cases.append(dadd)

            if "wildcard-address" in dapp_obj["destination-address"]:
                problem_cases.append(dapp_obj)
            else:
                mist_app["addresses"] = m_dadd

            for existing_mist_app in mist_apps.values():
                if existing_mist_app['name'] == mist_app['name']:
                    print("Duplicate names: "+mist_app['name'])
                    existing_app_copy = copy.deepcopy(existing_mist_app)
                    new_app_copy = copy.deepcopy(mist_app)
                    del existing_app_copy['description']
                    del new_app_copy['description']
                    if existing_app_copy == new_app_copy:
                        print('Fully duplicate app')
                    else:
                        mist_app['name'] += '_dupe' #TODO better dupe handling
            dapp_obj["mist_app"] = mist_app
            mist_apps[mist_app["name"]] = mist_app
            mist_services = [mist_app['name']]


            #Build Source Network
            source_zone = fztz['FromZone']
            if source_zone not in organized_nets:
                organized_nets[source_zone] = {'interface nets': {}, 'indirect nets': {}}

            #Build Interface Networks
            zints = junos_zones[source_zone]['interfaces']
            for zint in zints:
                zint_name = zint.split('.')[0]
                zint_unit = zint.split('.')[1]
                if zint_name.startswith(('irb', 'ge', 'xe', 'et')): #TODO add support for more interfaces
                    if zint_name in junos_interfaces:
                        if zint_unit in junos_interfaces[zint_name]['units']:
                            if junos_interfaces[zint_name]['units'][zint_unit]['address'] != "":
                                int_net = IPNetwork(junos_interfaces[zint_name]['units'][zint_unit]['address'])
                                if zint not in organized_nets[source_zone]['interface nets']:
                                    organized_nets[source_zone]['interface nets'][zint] = {
                                        'name': (source_zone+'_'+zint).replace('.','_').replace('-','_').replace(' ','_'),
                                        'subnet': str(int_net.cidr),
                                        'routed_for_networks': []
                                    }
                            else: print('No address for interface '+zint)
                    else: print('Could not find interface '+zint)
                else:
                    print('Interface '+zint+' not currently supported, ignoring')

            #Build Indirect Networks
            mist_tenants = []
            for source_addr in policy['Application']['match_set']['source-address']:
                addr_name = (source_zone+'_'+source_addr).replace('.','_').replace('-','_').replace(' ','_')
                if source_addr in junos_adds:
                    idx = 0
                    for result in junos_adds[source_addr]:
                        idx += 1
                        if result not in organized_nets[source_zone]['indirect nets']:
                            organized_nets[source_zone]['indirect nets'][result] = {
                                'name': addr_name+'_'+str(idx),
                                'subnet': result
                            }
                            mist_tenants.append(addr_name+'_'+str(idx))
                        else:  mist_tenants.append(organized_nets[source_zone]['indirect nets'][result]['name'])
                elif source_addr == "any":
                    if addr_name not in organized_nets[source_zone]['indirect nets']:
                        organized_nets[source_zone]['indirect nets'][addr_name] = {
                            'name': addr_name,
                            'subnet': '0.0.0.0/0'
                        }
                        mist_tenants.append(addr_name)
                    else: mist_tenants.append(organized_nets[source_zone]['indirect nets'][addr_name]['name'])
                else: print('Source address '+source_addr+' not found')

            #Build Policy
            mist_policy_name = policy_name.strip().replace('.','_').replace('-','_').replace(' ','_')
            mist_policies[policy_name] = {
                'name': mist_policy_name,
                'action': 'allow' if policy['Action'] == 'permit' else 'deny',
                'tenants': mist_tenants,
                'services': mist_services
            }

    #Indirectly attach indirect nets to their interface nets
    for zone_nets in organized_nets.values():
        for int_net in zone_nets['interface nets']:
            for indirect_net in zone_nets['indirect nets']:
                zone_nets['interface nets'][int_net]['routed_for_networks'].append(zone_nets['indirect nets'][indirect_net]['name'])


    with open('mist_apps.json', 'w+') as of:
        of.write(json.dumps(mist_apps, indent=4))
    print('Mist Apps created')

    with open('organized_nets.json', 'w+') as of:
        of.write(json.dumps(organized_nets, indent=4))

    with open('mist_policies.json', 'w+') as of:
        of.write(json.dumps(mist_policies, indent=4))

    with open("problem_cases_output.json", "w") as of:
        of.write(json.dumps(problem_cases, indent=4))

def push_apps():
    if not os.path.exists('mist_apps.json'):
        print('There are no Mist Applications ready to push, ingest configuration first')
        return

    mist_apps = {}
    with open('mist_apps.json') as maj:
        mist_apps = json.load(maj)
    print('There are '+str(len(mist_apps))+' Mist Applications ready to push')

    if UIToolsP3.getBool('Push now? '):
        for mapp in mist_apps.values():
            response = mistapi.api.v1.orgs.services.createOrgService(apisession, org_id, mapp)
            print(str(response.data))
            if response.status_code != 200:
                print('Error pushing '+mapp["name"]+'. Response: '+str(response.data))
    return

def push_nets():
    if not os.path.exists('organized_nets.json'):
        print('There are no Mist Networks ready to push, ingest configuration first')
        return

    with open('organized_nets.json') as onj:
        organized_nets = json.load(onj)

    if UIToolsP3.getBool('Push now? '):
        for zone in organized_nets.values():
            for indirect_net in zone['indirect nets'].values():
                response = mistapi.api.v1.orgs.networks.createOrgNetwork(apisession, org_id, indirect_net)
                print(str(response.data))
                if response.status_code != 200:
                    print('Error pushing ' + indirect_net["name"] + '. Response: ' + str(response.data))
            for int_net in zone['interface nets'].values():
                response = mistapi.api.v1.orgs.networks.createOrgNetwork(apisession, org_id, int_net)
                print(str(response.data))
                if response.status_code != 200:
                    print('Error pushing ' + int_net["name"] + '. Response: ' + str(response.data))
    return

def push_policies():
    if not os.path.exists('mist_policies.json'):
        print('There are no Mist Policies ready to push, ingest configuration first')
        return

    mist_apps = {}
    with open('mist_policies.json') as maj:
        mist_policies = json.load(maj)
    print('There are '+str(len(mist_policies))+' Mist Policies ready to push')

    if UIToolsP3.getBool('Push now? '):
        for mpol in mist_policies.values():
            response = mistapi.api.v1.orgs.servicepolicies.createOrgServicePolicy(apisession, org_id, mpol)
            print(str(response.data))
            if response.status_code != 200:
                print('Error pushing '+mpol["name"]+'. Response: '+str(response.data))
    return


def usage():
    print('''
-------------------------------------------------------------------------------

    Written by Eli Wulff (eli.wulff@hpe.com)

    This script is licensed under the MIT License.

-------------------------------------------------------------------------------
Description:
Python script to convert SRX security to policy to Mist. 

-------
Requirements:
mistapi: https://pypi.org/project/mistapi/

-------
Usage:
This script can be run as is (without parameters), or with the options below.
If no options are defined, or if options are missing, the missing options will
be asked by the script or the default values will be used.

It is recomended to use an environment file to store the required information
to request the Mist Cloud (see https://pypi.org/project/mistapi/ for more 
information about the available parameters).

-------
Script Parameters:
-h, --help              display this help
-o, --org_id=           Set the org_id
-e, --env=              define the env file to use (see mistapi env file 
                        documentation here: https://pypi.org/project/mistapi/)
                        default is "~/.mist_env"

-------
Examples:
python3 ./org_conf_backup.py
python3 ./org_conf_backup.py --org_id=203d3d02-xxxx-xxxx-xxxx-76896a3330f4 

''')
    sys.exit(0)

ingest_menu = UIToolsP3.Menu('Ingest Data Menu')
ingest_menu.menuOptions = {'From SRX': ingest_SRX, 'Back': 'Back', 'Quit': 'Quit'}

push_menu = UIToolsP3.Menu('Push to Mist')
push_menu.menuOptions = {'Applications': push_apps, 'Networks': push_nets, 'Back': 'Back', 'Quit': 'Quit'}

main_menu = UIToolsP3.Menu('Main Menu')
main_menu.menuOptions = {'Ingest Data': ingest_menu, 'Push to Mist':push_menu, 'Quit': 'Quit'}

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ho:e:c:", [
                                   "help", "org_id=", "env=", "conf_file="])
    except getopt.GetoptError as err:
        usage()

    for o, a in opts:
        if o in ["-h", "--help"]:
            usage()
        elif o in ["-o", "--org_id"]:
            org_id = a
        elif o in ["-e", "--env"]:
            env_file = a
        elif o in ["-c", "--conf_file"]:
            conf_file = a
        else:
            assert False, "unhandled option"

    global apisession
    apisession = mistapi.APISession(env_file=env_file)
    apisession.login()
    if not org_id: org_id = mistapi.cli.select_org(apisession)[0]
    main_menu.show()
