import requests
import re
import hashlib


R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow


def scanSite(target, output, data):
    result = {}
    
    try:
        positives = []
        negatives = []
        negatives_rp = []
        
        print ('\n\n' + G + '[+]' + Y + ' Site Vulnerabilities :' + W)
        responds = requests.get(target)

        # Redirection
        if responds.history:
            negatives.append('Redirections detected on the target')
            negatives.append('Root page / redirects to : ' + responds.url)
        else:
            positives.append('No redirections found on the target')

        # Server
        try:
            server_info = responds.headers.get('Server')
            if server_info != None:
                negatives.append('Server Information is not configured to be hidden HTTP responses header : ' + server_info)
                if not (server_info.strip().startswith('Apache')):
                    pass
                else:
                    # Detect Apache Outdated version
                    apache_version = re.search('Apache/(.*) ', server_info).group(1)
                    if re.search("3.\\d+.?", apache_version):
                        positives.append('Apache Version seems up-to-date : ' + apache_version)
                        pass
                    elif re.search("[0-2].\\d+.?", apache_version):
                        negatives.append('Outdated Apache Web Server Version detected : ' + apache_version)
                    else:
                        pass
            else:
                positives.append('Server Information is hidden')
        except:
            positives.append('Could not retrieve Server Information')

        # Detect Apache Version exposure misconfiguration via 404 response
        try:
            test_number = 0
            test_bool = False
            while test_number < 3:
                test_public_salt = 'SAlTACTUALLYjustARANDomStr1ng_veryUniqUEyo!'
                test_hash = hashlib.sha3_512((str(test_number) + test_public_salt).encode()).hexdigest()
                test_404_responds = requests.get(target + '/' + test_hash)
                if test_404_responds.status_code == 404:
                    if 'Apache/' in test_404_responds.text and ('The requested URL /' + test_hash + ' was not found on this server.') in test_404_responds.text:
                        negatives.append('404 Reponses exposed sensitive data about Web Server')
                        test_bool = True
                        break
                    else:
                        test_number = test_number + 1 
                        pass
            if test_bool:
                negatives.append('Server does not seem to handle 404 HTTP Responses')
            else:
                positives.append('Server handles 404 HTTP Responses')    
        except:
            pass

        # X-Powered-By
        try:
            powered_by = responds.headers.get('X-Powered-By')
            if powered_by != None:
                negatives.append('X-Powered-By is not configured to be hidden : ' + powered_by)
            else:
                positives.append('X-Powered-By is hidden')
        except:
            positives.append('Could not retrieve X-Powered-By')

        # X-AspNet-Version
        try:
            aspnet_version = responds.headers.get('X-AspNet-Version')
            if aspnet_version != None:
                negatives.append('X-AspNet-Version is exposed : ' + aspnet_version)
            else:
                positives.append('X-AspNet-Version is not detected')
        except:
            positives.append('Could not retrieve X-AspNet-Version')
        
        # X-AspNetMvc-Version
        try:
            aspnetmvc_version = responds.headers.get('X-AspNetMvc-Version')
            if aspnetmvc_version != None:
                negatives.append('X-AspNetMvc-Version is exposed : ' + aspnetmvc_version)
            else:
                positives.append('X-AspNetMvc-Version is not detected')
        except:
            positives.append('Could not retrieve X-AspNetMvc-Version')

        # Insecure communication & Unencrypted password submissions & Strict-Transport-Security
        if target.startswith('http://'):
            negatives.append('The network communication is not secure')
            negatives.append('Passwords are submitted unencrypted over the network')
        elif target.startswith('https://'):
            positives.append('The network communication is secure with SSL')
            positives.append('Data is encrypted over the network')
            try:
                strict_transport_security = responds.headers.get('Strict-Transport-Security')
                if strict_transport_security != None:
                    negatives.append('Strict-Transport-Security is not set for ensuring SSL Encryption')
                else:
                    positives.append('Strict-Transport-Security is set, ensured SSL Encryption')
            except:
                negatives.append('Could not retrieve Strict-Transport-Security for ensuring SSL Encryption')
        else:
            pass

        # Robots.txt
        try:       
            if requests.get(target + '/robots.txt').status_code == 200:
                negatives.append('Found /robots.txt file')
            elif requests.get(target + '/robots.txt').status_code == 404:
                positives.append('No /robots.txt file found')
            else:
                pass
        except:
            positives.append('Could not retrieve robot file')
        
        # sitemap.xml
        try:       
            if requests.get(target + '/sitemap.xml').status_code == 200:
                negatives.append('Found /sitemap.xml file')
            elif requests.get(target + '/sitemap.xml').status_code == 404:
                positives.append('No /sitemap.xml file found')
            else:
                pass
        except:
            positives.append('Could not retrieve robot file')   

        # Insecure HTTP cookies
        try:
            cookies_info = responds.headers.get('Set-Cookie')
            if 'Secure' in cookies_info:
                positives.append('Cookies HTTP Secure flag is set')
            else:
                negatives.append('Cookies HTTP Secure flag is not set')
            if 'HttpOnly' in cookies_info:
                positives.append('Cookies HTTP HttpOnly flag is set')
            else:
                negatives.append('Cookies HTTP HttpOnly flag is not set')
        except:
            negatives.append('No Set-Cookie HTTP Header retrieved')
            negatives.append('Cookies HTTP Secure flag is not set')
            negatives.append('Cookies HTTP HttpOnly flag is not set')

        # Missing HTTP Security X-XSS-Protection Header
        try:
            xss_protection = responds.headers.get('X-XSS-Protection')
            if xss_protection != None:
                positives.append('X-XSS-Protection is set')
            else:
                negatives.append('X-XSS-Protection is not available')
        except:
            negatives.append('X-XSS-Protection is not available')

        # Missing HTTP Security X-Content-Type-Options Header 
        try:
            content_type_options = responds.headers.get('X-Content-Type-Options')
            if content_type_options != None:
                positives.append('X-Content-Type-Options is set')
            else:
                negatives.append('X-Content-Type-Options is not set')
        except:
            negatives.append('X-Content-Type-Options is not set')

        # Missing HTTP Security X-Frame-Options Header 
        try:
            frame_options = responds.headers.get('X-Frame-Options')
            if frame_options != None:
                positives.append('The anti-clickjacking X-Frame-Options is available')
            else:
                negatives.append('The anti-clickjacking X-Frame-Options is unavailable')
        except:
            negatives.append('The anti-clickjacking X-Frame-Options is unretrievable')
        
        # ETags Server leaks
        try:
            etags = responds.headers.get('ETag')
            if '-' in etags :
                negatives.append('Etags could be leaking Server inodes')
            else:
                positives.append('Etags secured')
        except:
            positives.append('Etags headers is not set')

        # Missing HTTP Security Content-Security-Policy Header
        try:
            content_security_policy = responds.headers.get('Content-Security-Policy')
            if content_security_policy != None:
                positives.append('Content-Security-Policy is set')
            else:
                negatives.append('Missing Content-Security-Policy directive')
        except:
            negatives.append('Could not retrieve Content-Security-Policy')

        # Missing HTTP Security Access-Control-Allow-Origin Header
        try:
            access_control_allow_origin = responds.headers.get('Access-Control-Allow-Origin')
            if access_control_allow_origin != None:
                positives.append('Access-Control-Allow-Origin is set')
            else:
                negatives.append('Access-Control-Allow-Origin is not set ')
        except:
            negatives.append('Could not retrieve Access-Control-Allow-Origin')
        
        # Missing HTTP Security Referrer-Policy Header
        try:
            access_control_allow_origin = responds.headers.get('Referrer-Policy')
            if access_control_allow_origin != None:
                positives.append('Referrer-Policy is set, site information is under control')
            else:
                negatives.append('Referrer-Policy is not set, site information is not under control')
        except:
            negatives.append('Could not retrieve Referrer-Policy')

        # Missing HTTP Security Permissions-Policy Header
        try:
            access_control_allow_origin = responds.headers.get('Permissions-Policy')
            if access_control_allow_origin != None:
                positives.append('Permissions-Policy is set, featured site APIs are under control')
            else:
                negatives.append('Permissions-Policy is not set, site APIs are not under-control')
        except:
            negatives.append('Could not retrieve Permissions-Policy')
                 
        for negative in negatives:
            print('\n' + R + '[!] ' + negative)
            negatives_rp.append(negative + '\n')
        for positive in positives:
            print('\n' + G + '[+] ' + positive)
        
        if output != 'None':
            result['Negatives'] = negatives_rp

    except Exception as e:
        print('\n' + R + '[-]' + C + ' Exception : ' + W + str(e) + '\n')
        if output != 'None':
            result.update({'Exception':str(e)})

    if output != 'None':
        scanSite_output(output, data, result)
        print()
        
def scanSite_output(output, data, result):
    data['module-Site Vulns'] = result
