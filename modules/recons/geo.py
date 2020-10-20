from urllib.request import urlopen
from json import load
import sys
import socket


R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def ipInfo(addr): 
    url = 'https://ipinfo.io/' + addr + '/json'
    res = urlopen(url)
    #response from url(if res==None then check connection)
    info_data = load(res)
    #will load the json response into info data    
    return info_data


def geoip(ip, output, data):
    result = {}
    info_data = {}

    try:
        print ('\n\n' + G + '[+]' + Y + ' Geography IP :' + W + '\n')
        
        if is_valid_ipv4_address(ip):
            print(G + '[+]' + C + ' Valid IPv4 detected\n')
        elif is_valid_ipv6_address(ip):
            print(G + '[+]' + C + ' Valid IPv6 detected\n')            
        else:
            print(R + '[-]' + C + ' Invalid IP Address\n')
            return
 
        info_data = ipInfo(ip)
        for k, v in info_data.items():
            #will print the info data line by line
            print(G + '[+]' + C + ' ' + k.capitalize() + ' : ' + W + v)
            if output != 'None':
                result.update({k.capitalize():v})

    except Exception as e:
        print('\n' + R + '[-]' + C + ' Exception : ' + W + str(e) + '\n')
        if output != 'None':
            result.update({'Exception':str(e)})
    
    if output != 'None':
        geo_output(output, data, result)
        print()


def geo_output(output, data, result):
    data['module-Geography IP'] = result
