#!/usr/bin/env python3

import os
import sys
import atexit
import importlib.util
import platform
import argparse


# Colors
R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow


fail = False

# Check platform and privilege
if platform.system() == 'Linux':
	if os.geteuid() != 0:
		print('\n' + R + '[-]' + C + ' Please Run as Root!' + '\n')
		sys.exit()
	else:
		pass
else:
	pass

# Check and Install Packages
path_to_script = os.path.dirname(os.path.realpath(__file__))

with open(path_to_script + '/requirements.txt', 'r') as rqr:
	pkg_list = rqr.read().strip().split('\n')

print('\n' + G + '[+]' + C + ' Checking Dependencies...' + W + '\n')

for pkg in pkg_list:
	spec = importlib.util.find_spec(pkg)
	if spec is None:
		print(R + '[-]' + W + ' {}'.format(pkg) + C + ' is not Installed!' + W)
		fail = True
	else:
		pass
if fail == True:
	print('\n' + R + '[-]' + C + ' Please Execute ' + W + 'pip3 install -r requirements.txt' + C + ' to Install Missing Packages' + W + '\n')
	exit()

# Code version
version = '1.0.0'

# parser
parser = argparse.ArgumentParser(description='Gaidaros - The Land of The Broken Minds | v{}'.format(version))
parser.add_argument('url', help='Target URL')
parser.add_argument('--trace', help='Traceroute', action='store_true')

# Recon parser
recon_help = parser.add_argument_group('Recon Options')
recon_help.add_argument('--geo', help='Geography IP', action='store_true')
recon_help.add_argument('--headers', help='Header Information', action='store_true')
recon_help.add_argument('--sslinfo', help='SSL Certificate Information', action='store_true')
recon_help.add_argument('--whois', help='Whois Lookup', action='store_true')
recon_help.add_argument('--ps', help='Fast Port Scan', action='store_true')
recon_help.add_argument('--dns', help='DNS Enumeration', action='store_true')
recon_help.add_argument('--sub', help='Sub-Domain Enumeration', action='store_true')
recon_help.add_argument('--crawl', help='Crawl Target', action='store_true')
recon_help.add_argument('--dir', help='Directory Search', action='store_true')
recon_help.add_argument('--recon', help='Full Recon', action='store_true')

# Light Scan parser
light_help = parser.add_argument_group('Light Scan Options')
light_help.add_argument('--cve', help='Potential Apache CVE', action='store_true')
light_help.add_argument('--site', help='Site Vulnerabilities Scanner', action='store_true')
light_help.add_argument('--virus', help='Malware URL Scanner', action='store_true')
light_help.add_argument('--light', help='Full Web Light Scan', action='store_true')

# OWASP Scan parser
owasp_help = parser.add_argument_group('OWASP Scan Options')
owasp_help.add_argument('--xss', help='Cross Site Scripting - UNDER DEVELOPMENT', action='store_true')
owasp_help.add_argument('--sql', help='SQL Injection Scripting - UNDER DEVELOPMENT', action='store_true')
owasp_help.add_argument('--csrf', help='Cross Site Request Forgery - UNDER DEVELOPMENT', action='store_true')
owasp_help.add_argument('--owasp', help='Full OWASP Scan - UNDER DEVELOPMENT', action='store_true')

# Report parser
report_help = parser.add_argument_group('Report Options')
report_help.add_argument('--report', help='Post-scan Reporting', action='store_true')

# Full Scan parser
full_help = parser.add_argument_group('Full Scan Options')
full_help.add_argument('--full', help='Full Scan', action='store_true')

# Extra Options parser
ext_help = parser.add_argument_group('Extra Options')
ext_help.add_argument('-t', type=int, help='Number of Threads [ Default : 30 ]')
ext_help.add_argument('-T', type=float, help='Request Timeout [ Default : 30.0 ]')
ext_help.add_argument('-w', help='Path to Wordlist [ Default : wordlists/dirb_common.txt ]')
ext_help.add_argument('-r', action='store_true', help='Allow Redirect [ Default : False ]')
ext_help.add_argument('-s', action='store_false', help='Toggle SSL Verification [ Default : True ]')
ext_help.add_argument('-d', help='Custom DNS Servers [ Default : 1.1.1.1 ]')
ext_help.add_argument('-e', help='File Extensions [ Example : txt, xml, php ]')
ext_help.add_argument('-m', help='Traceroute Mode [ Default : UDP ] [ Available : TCP, ICMP ]')
ext_help.add_argument('-p', type=int, help='Port for Traceroute [ Default : 80 / 33434 ]')
ext_help.add_argument('-tt', type=float, help='Traceroute Timeout [ Default : 1.0 ]')
ext_help.add_argument('-o', help='Export Output [ Default : txt ] [ Available : xml, csv ]')
ext_help.set_defaults(
	t=30,
	T=30.0,
	w='wordlists/dirb_common.txt',
	r=False,
	s=True,
	d='1.1.1.1',
	e='',
	m='UDP',
	p=33434,
	tt=1.0,
	o='txt')

args = parser.parse_args()

# Recon args
target = args.url
headinfo = args.headers
sslinfo = args.sslinfo
whois = args.whois
crawl = args.crawl
dns = args.dns
trace = args.trace
dirrec = args.dir
pscan = args.ps
geo = args.geo
recon = args.recon

# Light Scan args
cve = args.cve
site = args.site
virus = args.virus
light = args.light

# OWASP Scan args

# Reports args
report = args.report

# Full Scan args
full = args.full

threads = args.t
tout = args.T
wdlist = args.w
redir = args.r
sslv = args.s
dserv = args.d
filext = args.e
subd = args.sub
mode = args.m
port = args.p
tr_tout = args.tt
output = args.o

import socket
import requests
import datetime
import ipaddress
import tldextract

type_ip = False
data = {}
meta = {}

def banner():
	banner = r'''
  ▄████   ▄▄▄        ██▓ ▓█████▄   ▄▄▄        ██▀███    ▒█████     ██████ 
 ██▒ ▀█▒ ▒████▄     ▓██▒ ▒██▀ ██▌ ▒████▄     ▓██ ▒ ██▒ ▒██▒  ██▒ ▒██    ▒ 
▒██░▄▄▄░ ▒██  ▀█▄   ▒██▒ ░██   █▌ ▒██  ▀█▄   ▓██ ░▄█ ▒ ▒██░  ██▒ ░ ▓██▄   
░▓█  ██▓ ░██▄▄▄▄██  ░██░ ░▓█▄   ▌ ░██▄▄▄▄██  ▒██▀▀█▄   ▒██   ██░   ▒   ██▒
░▒▓███▀▒  ▓█   ▓██▒ ░██░ ░▒████▓   ▓█   ▓██▒ ░██▓ ▒██▒ ░ ████▓▒░ ▒██████▒▒
 ░▒   ▒   ▒▒   ▓▒█░ ░▓    ▒▒▓  ▒   ▒▒   ▓▒█░ ░ ▒▓ ░▒▓░ ░ ▒░▒░▒░  ▒ ▒▓▒ ▒ ░
  ░   ░    ▒   ▒▒ ░  ▒ ░  ░ ▒  ▒    ▒   ▒▒ ░   ░▒ ░ ▒░   ░ ▒ ▒░  ░ ░▒  ░ ░
░ ░   ░    ░   ▒     ▒ ░  ░ ░  ░    ░   ▒      ░░   ░  ░ ░ ░ ▒   ░  ░  ░  
      ░        ░  ░  ░      ░           ░  ░    ░          ░ ░         ░  
                       ░                                                     
'''
	print (R + banner + W)
	print (R + '[>]' + Y + ' Created By : ' + W + 'Gaidaros Team' + R + ' [<]\t[>]' + Y + ' Version : ' + W + version + R +' [<]' + W + '\n\n')

def ver_check():
	print(G + '[+]' + C + ' Checking for Updates...', end='')
	ver_url = 'https://raw.githubusercontent.com/Ch3lLIST4/Gaidaros/main/version.txt'
	try:
		ver_rqst = requests.get(ver_url, timeout=5)
		ver_sc = ver_rqst.status_code
		if ver_sc == 200:
			github_ver = ver_rqst.text
			github_ver = github_ver.strip()
			if version == github_ver:
				print(C + '[' + G + ' Up-To-Date ' + C +']' + '\n')
			else:
				print(C + '[' + G + ' Available : {} '.format(github_ver) + C + ']' + '\n')
		else:
			print(C + '[' + R + ' Status : {} '.format(ver_sc) + C + ']' + '\n')
	except Exception as e:
		print('\n\n' + R + '[-]' + C + ' Exception : ' + W + str(e))
		sys.exit()

# Full Recon
def full_recon():
	from modules.geo import geoip
	from modules.headers import headers
	from modules.sslinfo import cert
	from modules.whois import whois_lookup
	from modules.portscan import ps
	from modules.dns import dnsrec
	from modules.subdom import subdomains
	from modules.crawler import crawler
	from modules.dirrec import hammer
	# 1. Geo-IP
	geoip(ip, output, data)
	# 2. HTTP Headers
	headers(target, output, data)
	# 3. SSL Cert Information
	if target.startswith('https://'):
		cert(hostname, output, data)
	else:
		print('\n' + Y + '[!]' + ' Skipping SSL Certification Scan ' + W)
		pass
	# 4. Whois Lookup
	whois_lookup(ip, output, data)
	# 5. Port Scan
	ps(ip, output, data)
	# 6. DNS Enumeration
	dnsrec(domain, output, data)
	# 7. Sub-Domain Enumeration
	if type_ip == False:
		subdomains(domain, tout, output, data)
	else:
		print('\n' + Y + '[!]' + ' Skipping Sub-Domain Enumeration ' + W)
		pass
	# 8. Web Crawling
	crawler(target, output, data)
	# 9. Directory Traversing
	hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext)

# Light Scan
def light_scan():
	from modules.apacheScan_CVE import checkVulns
	from modules.site import scanSite
	from modules.virus import scanVirus
	# 1. CVE Checkers
	checkVulns(target, output, data)
	# 2. Site Vulnerabilities Scan
	scanSite(target, output, data)
	# 3. Virus Scan
	scanVirus(target, output, data)

# OWASP Scan

# Reports

# Full Scan
def full_scan():
	# 1. Reconnaisance
	full_recon()
	# 2. Light Vuln Scan
	light_scan()
	# 3. OWASP Scan
	# 4. Reports


try:
	banner()
	ver_check()

	if target.startswith(('http://', 'https://')) == False:
		print(R + '[-]' + C + ' Protocol Missing, Include ' + W + 'http://' + C + ' or ' + W + 'https://' + '\n')
		sys.exit()
	else:
		pass

	if target.endswith('/') == True:
		target = target[:-1]
	else:
		pass

	print (G + '[+]' + C + ' Target : ' + W + target)
	ext = tldextract.extract(target)
	domain = ext.registered_domain
	hostname = '.'.join(part for part in ext if part)

	try:
		ipaddress.ip_address(hostname)
		type_ip = True
		ip = hostname
	except:
		try:
			ip = socket.gethostbyname(hostname)
			print ('\n' + G + '[+]' + C + ' IP Address : ' + W + str(ip))
		except Exception as e:
			print ('\n' + R + '[+]' + C + ' Unable to Get IP : ' + W + str(e))
			if '[Errno -2]' in str(e):
				sys.exit()
			else:
				pass
	
	start_time = datetime.datetime.now()

	meta.update({'Version': str(version)})
	meta.update({'Date': str(datetime.date.today())})
	meta.update({'Target': str(target)})
	meta.update({'IP Address': str(ip)})
	meta.update({'Start Time': str(start_time.strftime('%I:%M:%S %p'))})
	data['module-Gaidaros'] = meta

	if output != 'None':
		fname = os.getcwd() + '/dumps/' + hostname + '.' + output
		output = {
			'format': output,
			'file': fname,
			'export': False
			}

	from modules.export import export
	
	if recon == True:
		full_recon()
	
	if geo == True:
		from modules.geo import geoip
		geoip(ip, output, data)
	
	if headinfo == True:
		from modules.headers import headers
		headers(target, output, data)

	if sslinfo == True and target.startswith('https://'):
		from modules.sslinfo import cert
		cert(hostname, output, data)
	elif sslinfo == True and not target.startswith('https://'):
		print('\n' + R + '[-]' + C + ' SSL Certification Scan is Not Supported for HTTP protocol' + W + '\n')
		sys.exit()
	else:
		pass

	if whois == True:
		from modules.whois import whois_lookup
		whois_lookup(ip, output, data)

	if crawl == True:
		from modules.crawler import crawler
		crawler(target, output, data)

	if dns == True:
		from modules.dns import dnsrec
		dnsrec(domain, output, data)

	if subd == True and type_ip == False:
		from modules.subdom import subdomains
		subdomains(domain, tout, output, data)
	elif subd == True and type_ip == True:
		print(R + '[-]' + C + ' Sub-Domain Enumeration is Not Supported for IP Addresses' + W + '\n')
		sys.exit()
	else:
		pass

	if trace == True:
		from modules.traceroute import troute
		if mode == 'TCP' and port == 33434:
			port = 80
			troute(ip, mode, port, tr_tout, output, data)
		else:
			troute(ip, mode, port, tr_tout, output, data)

	if pscan == True:
		from modules.portscan import ps
		ps(ip, output, data)

	if dirrec == True:
		from modules.dirrec import hammer
		hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext)
	
	if cve == True:	
		from modules.apacheScan_CVE import checkVulns
		checkVulns(target, output, data)
	
	if site == True:
		from modules.site import scanSite
		scanSite(target, output, data)
	
	if virus == True:
		from modules.virus import scanVirus
		scanVirus(target, output, data)
	
	if light == True:
		light_scan()
		
	if report == True:
		from modules.report import report
		report(target)

	if full == True:
		full_scan()
	
	if any([recon, geo, headinfo, sslinfo, whois, crawl, dns, subd, trace, pscan, dirrec, cve, site, virus, light, report, full]) != True:
		print ('\n' + R + '[-] Error : ' + C + 'Atleast One Argument is Required with URL' + W)
		output = 'None'
		sys.exit()
	
	end_time = datetime.datetime.now() - start_time
	print ('\n' + G + '[+]' + C + ' Completed in ' + W + str(end_time) + '\n')

	@atexit.register
	def call_export():
		meta.update({'End Time': str(datetime.datetime.now().strftime('%I:%M:%S %p'))})
		meta.update({'Completion Time': str(end_time)})
		if output != 'None':
			output['export'] = True
			export(output, data)

	sys.exit()
except KeyboardInterrupt:
	print (R + '[-]' + C + ' Keyboard Interrupt.' + W + '\n')
	sys.exit()
