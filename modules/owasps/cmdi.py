
import tldextract
import argparse
import sys
import bs4
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import requests
import urllib3
import csv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow


def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    try:
        # get the form action (target url)
        action = form.attrs.get("action").lower()
        # get the form method (POST, GET, etc.)
        method = form.attrs.get("method", "get").lower()
        # get all the input details such as type and name
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        # put everything to the resulting dictionary
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details
    except AttributeError as N:
        print(G + "[+]" + C + f" No action form detected on this site" + W)
        return None
    except Exception as e:
        print('\n' + R + '[-] Exception : ' + C + str(e) + W)


def submit_form(form_details, url, value):
    """
    Submits a form given in `form_details`
    Params:
        form_details (list): a dictionary that contain form information
        url (str): the original URL that contain that form
        value (str): this will be replaced to all text and search inputs
    Returns the HTTP Response after form submission
    """
    # construct the full URL (if the url provided in action is relative)
    try:
        target_url = urljoin(url, form_details["action"])
        # get the inputs
        inputs = form_details["inputs"]
        data = {}
        for input in inputs:
            # replace all text and search values with `value`
            if input["type"] == "text" or input["type"] == "search":
                input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                # if input name and value are not None,
                # then add them to the data of form submission
                data[input_name] = input_value

        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        else:
            # GET request
            return requests.get(target_url, params=data)
    except Exception as e:
        print('\n' + R + '[-] Exception : ' + C + str(e) + W)


def scan_cmdi(url, value_forms_malforms, cmdi_data):
    """
    Given a `url`, it prints all cmdi vulnerable forms and
    returns True if any is vulnerable, False otherwise
    """
    try:

        # get all the forms from the URL
        forms = get_all_forms(url)
        print(G + "[+]" + C + f" Detected {len(forms)} forms on {url}" + W)
        cmdi_data.append(f"Detected {len(forms)} forms on {url}")
        value_forms_malforms[0] = value_forms_malforms[0] + len(forms)
        #os_script = "a | ping -c 2 127.0.0.1"
        #getpayload
        payload_path = './dictionary/payload.csv'
        inps = []
        outcs = []
        with open(payload_path) as f:
            readCSV = csv.reader(f, delimiter=',')
            for row in readCSV:
                inp = row[0]
                outc = row[1]
                #print('in: ',inp,', out: ',outc)
                inps.append(inp)
                outcs.append(outc)
        length = len(inps)
        # returning value
        is_vulnerable = False
        # iterate over all forms
        print('Start loop payload:')
        for i in range(length):
            inc = inps[i]
            outc = outcs[i]
            os_script = inc
            print('Loop ',i,': In:',inc,'Out:',outc)
            for form in forms:
                form_details = get_form_details(form)
                if form_details == None:
                    break
                content = submit_form(form_details, url, os_script).content.decode('latin-1')
                #content = 'PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data'
                #print('content:',content)
                if outc in content:
                    print(R + f"[-] Command Injection Detected on {url}" + W)
                    print(R + "[-]" + C + " Form details:" + W)
                    pprint(form_details)
                    cmdi_data.append(f"Command Injection Detected on {url} | Form details: {form_details}")
                    print(W)
                    value_forms_malforms[1] = value_forms_malforms[1] + 1
                    is_vulnerable = True
                    # won't break because we want to print other available vulnerable forms

        if is_vulnerable == True:
            print(R + "[-]" + f" Command Injection detected on {url}" + W)
            cmdi_data.append(f"Command Injection detected on {url}\n")
        else:
            print(G + "[+]" + f" Command Injection not detected on {url}" + W)
            cmdi_data.append(f"Command Injection not detected on {url}\n")

    except Exception as e:
        print(R + '[-] Exception : ' + C + str(e) + W)


def cmdi(target, output, data):
    result = {}
    cmdi_data = []

    try:
        print ('\n\n' + G + '[+]' + Y + ' OS Command Injection (CMDi) :' + W + '\n')

        user_agent = {
            'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'
        }
        # get soup
        try:
            rqst = requests.get(target, headers=user_agent, verify=False)
        except Exception as e:
            print(R + '[-] Exception : ' + C + str(e) + W)
            exit()

        sc = rqst.status_code
        if sc == 200:
            int_total = []
            value_forms_malforms = [0,0]

            page = rqst.content
            soup = bs4.BeautifulSoup(page, 'lxml')

            ext =  tldextract.extract(target)
            domain = ext.registered_domain

            links = soup.find_all('a')
            for link in links:
                url = link.get('href')
                if url != None:
                    if not "http://" in url or "https://" in url:
                        url = target +  "/" + url
                    if not '#' in url:
                        if domain in url:
                            int_total.append(url)

            int_total = set(int_total)

            scan_cmdi(target, value_forms_malforms, cmdi_data)
            for int in int_total:
                scan_cmdi(int, value_forms_malforms, cmdi_data)

            print("\n" + G + "[+] " + str(len(int_total) + 1) + C + " total urls tested" + W)
            print(G + "[+] " + str(value_forms_malforms[0]) + C + " total forms detected" + W)
            if value_forms_malforms[1] == 0:
                print(G + "[+] " + str(value_forms_malforms[1]) + C + " total malicious forms detected" + W)
            else:
                print(R + "[-] " + str(value_forms_malforms[1]) + C + " total malicious forms detected" + W)

        else:
            print(R + '[-]' + C + ' Response code returned is not 200' + W)

        if output != 'None':
            result['CMDi'] = cmdi_data

    except Exception as e:
        print(R + '[-] Exception : ' + C + str(e) + W)
        if output != 'None':
            result.update({'Exception':str(e)})

    if output != 'None':
        cmdi_output(output, data, result)
        print()


def cmdi_output(output, data, result):
    data['module-OS Command Injection'] = result
