#!/usr/bin/python

import sys
import os
import requests
import re

class bcolors:
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    NEUTRAL = '\033[94m'
    FAIL = '\033[91m'
    ENDC = '\033[0m' 
    BOLD = '\033[1m'

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

def checkVulns(target, output, data):
    result = {}
    try:
        print ('\n\n' + G + '[+]' + Y + ' Apache CVE :' + W + '\n')
        
        responds = requests.get(target)
        server_name = responds.headers.get('Server')
        if not (server_name.strip().startswith('Apache')):
            print(R + '[-]' + C + ' Server does not seem to be an Apache Server : ' + W + server_name + '\n')
            return
        else:
            print(G + '[+]' + C + ' Apache Server detected : ' + W + server_name + '\n')
            apache_version = re.search('Apache/(.*) ', server_name).group(1)
            x = re.search("[0-3].\\d+.?", apache_version)
            if x:
                print(G + '[+]' + C + ' Apache Version detected : ' + W + apache_version + '\n')
            else:
                print(R + '[-]' + C + ' Could not retrieve Apache Version : ' + W + apache_version + '\n')
                return

        cve_path = './dictionary/apache_CVE.txt'
              
        print(G + '[+]' + C + ' CVE Path : ' + W + cve_path)
        
        vulns = []
        vulns_rp = []
        start = False
        f = open(cve_path, 'r')
        for line in f.readlines():
            if start == True:
                if line != "\n":
                    vulns.append(line)
                    vulns_rp.append(line.replace('\t', ''))
                if not line.startswith('\t'):
                    start = False
                    break
            if line.strip("\n") == apache_version:
                start = True

        if (len(vulns) != 0):
            varVuln = 'vulnerabilities!'
            if (len(vulns) == 1):
                varVuln = 'vulnerability!'
            print(G + '\n[+]' + C + ' Found' + bcolors.FAIL + bcolors.BOLD, len(vulns), bcolors.ENDC + varVuln)
            print(G + '\n[+]' + C + ' Apache ' + bcolors.NEUTRAL + bcolors.BOLD + apache_version + bcolors.ENDC + ' is vulnerable to the following:' + '\n')
            print(bcolors.FAIL + "".join(vulns))
        else:
            print(bcolors.FAIL + '\n[-]' + ' I am sorry but we could\'t find any vulnerabilities in our database for ' + bcolors.NEUTRAL + bcolors.BOLD + 'Apache ' + apache_version + bcolors.ENDC + '.')
        
        if output != 'None':
            result['CVE-ID'] = vulns_rp
        
    except Exception as e:
        print('\n' + R + '[-]' + C + ' Exception : ' + W + str(e) + '\n')
        if output != 'None':
            result.update({'Exception':str(e)})

    if output != 'None':
        CVE_output(output, data, result)

def CVE_output(output, data, result):
    data['module-Apache CVE'] = result
