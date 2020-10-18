## Gaidaros
[![GitHub last commit](https://img.shields.io/github/last-commit/Ch3lLIST4/Gaidaros?logo=github)](#)
[![GitHub repo size](https://img.shields.io/github/repo-size/Ch3lLIST4/Gaidaros?color=red&logo=github)](#)
[![GitHub top language](https://img.shields.io/github/languages/top/Ch3lLIST4/Gaidaros?logo=python&logoColor=yellow)](https://www.python.org/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/icmplib?color=purple&label=version&logo=python&logoColor=yellow)](https://www.python.org/downloads/)
[![GitHub issues](https://img.shields.io/github/issues-raw/Ch3lLIST4/Gaidaros?logo=github)](#)


Gaidaros - The Land of The Broken Minds
<br/><br/><br/>
<img src="https://github.com/Ch3lLIST4/Gaidaros/blob/main/images/banner.jpg" alt="donkey_banner">
<br/><br/>

Gaidaros is designed to be a fast and simple open-source vulnerability security scanner and penetration testing tool concentrating on Apache Web Server. The tool follows the rule of pentesting checklist that automates the process of detecting and exploiting the target Web Server and its Web Applications' vulnerabilities, also helps minimizing the time and effort of anyone looking forward to pentest a particular Web Server, and finally providing well-designed afterward reports. It comes with a powerful detection engine, numerous niche features for the ultimate penetration tester.

Gaidaros specializes in the Reconnaissance Phase with the help of OSINT Framework and gets the most out of it. This tool, by any means, is not recommended to be a replacement for pentesters, it can only be recommended to be used as a versatile quick scanner and a helpful time saver. All you need is the target url, and you are ready to go.

## Featured 

- [Apache-Vulns](https://github.com/styx00/Apache-Vulns)
- [Python for OSINT Tooling](https://hakin9.org/product/python-for-osint-tooling/)


## Tested on

- Kali Linux
> Most of the required packages are already pre-installed on Kali Linux 

## Features

- Full Reconnaissance
- Apache Vuln Scanner
- Common Web Application Vuln Scanner
- Post-scan Reporting

## Installation

Gaidaros is a Python script so you need [Python](https://www.python.org/downloads/) to run this program
```bash
sudo apt install python3
```
Also, pip3 is needed for the essential python packages
```bash
sudo apt install python3-pip
```
Preferably, you can download Gaidaros by cloning the Git repository:
```bash
git clone https://github.com/Ch3lLIST4/Gaidaros.git 
```
Install the necessary pip3 requirements for the project
```bash
cd Gaidaros
pip3 install -r requirements.txt
```
Gaidaros works out of the box with Python version 3.x on any platform. However, it is recommended to be used on Kali Linux

## Usage

Using help command for a list of usage
```bash
sudo python3 gaidaros.py -h
```
Supply with your own apikeys in order to use some modules
```bash
nano ./conf/keys.json
```
Btw you need to install python-docx package for Python3 to generate report
```bash
pip3 install python-docx
```

## Video
[![donkey_thumbnail](https://img.youtube.com/vi/BbYwEgnk1dE/0.jpg)](https://www.youtube.com/watch?v=dQw4w9WgXcQ)
