import requests
import json


R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow


def scanVirus(target, output, data):
    result = {}
    try:
        print ('\n\n' + G + '[+]' + Y + ' Malware Scanner :' + W + '\n')
        
        with open('conf/keys.json', 'r') as keyfile:
            json_read = keyfile.read()
        json_load = json.loads(json_read)
        virus_key = json_load['api_keys'][1]['virustotal']
        
        if virus_key == None:
            print(R + '[-]' + C + ' Please provide a key in ./conf/keys.json ' + W + '\n')
            return
        else:
            response = requests.get('https://www.virustotal.com/vtapi/v2/url/report?apikey=' + virus_key + '&resource=' + target)
            json_data = json.loads(response.text)

            count = 0
            for k,v in json_data.items():
                if k != 'scans':
                    print(G + '[+] ' +  C + str(k).capitalize() + ' : ' + W + str(v))
                elif k == 'scans':
                    print(G + '[+] ' +  C + str(k).capitalize() + ' :' + W)
                    for engine in v.items():
                        if (engine[1].get('detected') == False):
                            print('      |--  ' + C + engine[0] + ' : ' + G + str(engine[1]) + W)
                        elif(engine[1].get('detected') == True):
                            print('      |--  ' + C + engine[0] + ' : ' + R + str(engine[1]) + W)
                            count = count + 1
                        if output != 'None':
                                result.update({engine[0]:engine[1]})
                    result.update({'Positives':count})
                else:
                    pass

            if count > 0:
                print('\n' + R + '[!] ' + str(count) + ' total engines confirmed your site is malicious. Your site is malicious, check data for more info')
            elif count == 0:
                print('\n' + G + '[+] ' + str(count) + ' total engines detected any malware. Your site looks secure')
            else:
                pass
            
    except Exception as e:
        print('\n\n' + R + '[-]' + C + ' Exception : ' + W + str(e))
        if output != 'None':
            result.update({'Exception':str(e)})
    
    if output != 'None':
        scanVirus_output(output, data, result)
        print()

def scanVirus_output(output, data, result):
    data['module-Virus Total'] = result
