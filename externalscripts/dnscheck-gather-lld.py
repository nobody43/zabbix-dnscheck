#!/usr/bin/env python3

## Installation instructions: https://github.com/nobodysu/zabbix-dnscheck ##

dnsWait = '1'     # each dns query will take no more than one second (multiple DNS servers ARE processed)

hostPath = 'host'
#hostPath = r'/usr/bin/host'             # if host isn't in PATH
pythonPath = 'python3'
#pythonPath = '/usr/local/bin/python3'   # if python isn't in PATH
senderPyPath = r'/usr/lib/zabbix/externalscripts/dnscheck-send.py'

## End of configuration ##

import sys
import re
import json
import subprocess

hostdns = sys.argv[2]
hosthost = sys.argv[3]

ptrCheck = sys.argv[4]
IPv6Check = sys.argv[5]
mxCheck = sys.argv[6]
txtCheck = sys.argv[7]

jsonData = []
senderData = []

if re.search('^\d+\.\d+\.\d+\.\d+$', hostdns): 
    print(sys.argv[0] + ": IP addresses are not supported as main input, a DNS name must be provided.")
    sys.exit(1)

hostOut = subprocess.getoutput(hostPath + ' -W ' +  dnsWait + ' ' + hostdns)

ipv4Re = re.findall(r' has address (.+)$', hostOut, re.I | re.M)
ipv4Re.sort()   # prevent ips mess up on each query
error = 'no'

if ipv4Re:
    for num4, ip4 in enumerate(ipv4Re, start=1):
        num4 = str(num4)
        jsonData.append({'{#HOSTNAME}':hosthost, '{#IPV4NUM}':num4})
        senderData.append('"' + hosthost + '" dnscheck.ipv4[' + num4 + '] "' + ip4 + '"')   # "example.org" dnscheck.ipv4[1] "192.0.2.1"

        if ptrCheck == 'ptrYES':
            hostPtr4Out = subprocess.getoutput(hostPath + ' -W ' + dnsWait + ' ' + ip4)

            ptr4Re = re.findall(' domain name pointer (.+)$', hostPtr4Out, re.I | re.M)

            if ptr4Re:
                for i in ptr4Re:
                    jsonData.append({'{#HOSTNAME}':hosthost, '{#PTR4NUM}':num4})
                    senderData.append('"' + hosthost + '" dnscheck.ptr4[' + num4 + '] "' + i + '"')   # "example.org" dnscheck.ptr4[1] "example.org."

                if len(ptr4Re) > 1:   # if more than one PTR per IP were found
                    jsonData.append({'{#HOSTNAME}':hosthost, '{#PTR4NUM}':num4})
                    senderData.append('"' + hosthost + '" dnscheck.ptr4[' + num4 + '] "MULTIPTR"')

            elif hostPtr4Out.find('no servers could be reached') != -1:
                jsonData.append({'{#HOSTNAME}':hosthost, '{#PTR4NUM}':num4})
                senderData.append('"' + hosthost + '" dnscheck.ptr4[' + num4 + '] "TIMEOUT"')

            else:
                jsonData.append({'{#HOSTNAME}':hosthost, '{#PTR4NUM}':num4})
                senderData.append('"' + hosthost + '" dnscheck.ptr4[' + num4 + '] "NOPTR"')

elif hostOut.find('no servers could be reached') != -1:
    jsonData.append({'{#HOSTNAME}':hosthost, '{#IPV4NUM}':'1'})
    senderData.append('"' + hosthost + '" dnscheck.ipv4[1] "TIMEOUT"')

    error = 'yes'   # do not process any other entry on error

elif hostdns == '':
    jsonData.append({'{#HOSTNAME}':hosthost, '{#IPV4NUM}':'1'})
    senderData.append('"' + hosthost + '" dnscheck.ipv4[1] "NODNS"')

    error = 'yes'

else:
    jsonData.append({'{#HOSTNAME}':hosthost, '{#IPV4NUM}':'1'})
    senderData.append('"' + hosthost + '" dnscheck.ipv4[1] "NOIPV4"')


if IPv6Check == 'ipv6YES' and error == 'no':
    ipv6Re = re.findall(' has IPv6 address (.+)$', hostOut, re.I | re.M)
    ipv6Re.sort()

    if ipv6Re:
        for num6, ip6 in enumerate(ipv6Re, start=1):
            num6 = str(num6)
            jsonData.append({'{#HOSTNAME}':hosthost, '{#IPV6NUM}':num6})
            senderData.append('"' + hosthost + '" dnscheck.ipv6[' + num6 + '] "' + ip6 + '"')

            if ptrCheck == 'ptrYES':
                hostPtr6Out = subprocess.getoutput(hostPath + ' -W ' + dnsWait + ' ' + ip6)

                ptr6Re = re.findall(' domain name pointer (.+)$', hostPtr6Out, re.I | re.M)

                if ptr6Re:
                    for i in ptr6Re:
                        jsonData.append({'{#HOSTNAME}':hosthost, '{#PTR6NUM}':num6})
                        senderData.append('"' + hosthost + '" dnscheck.ptr6[' + num6 + '] "' + i + '"')

                    if len(ptr6Re) > 1:   # if more than one PTR per IP were found
                        jsonData.append({'{#HOSTNAME}':hosthost, '{#PTR6NUM}':num6})
                        senderData.append('"' + hosthost + '" dnscheck.ptr6[' + num6 + '] "MULTIPTR"')

                elif hostPtr6Out.find('no servers could be reached') != -1:
                    jsonData.append({'{#HOSTNAME}':hosthost, '{#PTR6NUM}':num6})
                    senderData.append('"' + hosthost + '" dnscheck.ptr6[' + num6 + '] "TIMEOUT"')

                else:
                    jsonData.append({'{#HOSTNAME}':hosthost, '{#PTR6NUM}':num6})
                    senderData.append('"' + hosthost + '" dnscheck.ptr6[' + num6 + '] "NOPTR"')

    elif hostOut.find('no servers could be reached') != -1:
        jsonData.append({'{#HOSTNAME}':hosthost, '{#IPV6NUM}':'1'})
        senderData.append('"' + hosthost + '" dnscheck.ipv6[1] "TIMEOUT"')

    else:
        jsonData.append({'{#HOSTNAME}':hosthost, '{#IPV6NUM}':'1'})
        senderData.append('"' + hosthost + '" dnscheck.ipv6[1] "NOIPV6"')


if mxCheck == 'mxYES' and error == 'no':
    mxRe = re.findall(r' mail is handled by\s+(\d+)\s+(.+)$', hostOut, re.I | re.M)
    mxRe.sort()

    if mxRe:
        for numMX, (valMXpri, valMX) in enumerate(mxRe, start=1):
            numMX = str(numMX)
            jsonData.append({'{#HOSTNAME}':hosthost, '{#MXNUM}':numMX})
            senderData.append('"' + hosthost + '" dnscheck.mx[' + numMX + '] "' + valMX + '"')
            jsonData.append({'{#HOSTNAME}':hosthost, '{#MXPRINUM}':numMX})
            senderData.append('"' + hosthost + '" dnscheck.mxpri[' + numMX + '] "' + valMXpri + '"')

    elif hostOut.find('no servers could be reached') != -1:
        jsonData.append({'{#HOSTNAME}':hosthost, '{#MXNUM}':'1'})
        senderData.append('"' + hosthost + '" dnscheck.mx[1] "TIMEOUT"')
        #jsonData.append({'{#HOSTNAME}':hosthost, '{#MXPRINUM}':'1'})   # priority is not gathered when no MX is present
        #senderData.append('"' + hosthost + '" dnscheck.mxpri[1] "TIMEOUT"')

    else:
        jsonData.append({'{#HOSTNAME}':hosthost, '{#MXNUM}':'1'})
        senderData.append('"' + hosthost + '" dnscheck.mx[1] "NOMX"')
        #jsonData.append({'{#HOSTNAME}':hosthost, '{#MXPRINUM}':'1'})
        #senderData.append('"' + hosthost + '" dnscheck.mxpri[1] "NOMX"')


if txtCheck == 'txtYES' and error == 'no':
    txtOut = subprocess.getoutput(hostPath + ' -W ' + dnsWait + ' -t txt ' + hostdns)

    txtRe = re.findall(' descriptive text (.+)$', txtOut, re.I | re.M)
    txtRe.sort()

    if txtRe:
        for numTxt, valTxt in enumerate(txtRe, start=1):
            if not re.search('^".+"$', valTxt):   # if value is not encased in quotes
                valTxt = '"' + valTxt + '"'

            numTxt = str(numTxt)
            jsonData.append({'{#HOSTNAME}':hosthost, '{#TXTNUM}':numTxt})
            senderData.append('"' + hosthost + '" dnscheck.txt[' + numTxt + '] ' + valTxt)

    elif hostOut.find('no servers could be reached') != -1:
        jsonData.append({'{#HOSTNAME}':hosthost, '{#TXTNUM}':'1'})
        senderData.append('"' + hosthost + '" dnscheck.txt[1] "TIMEOUT"')

    else:
        jsonData.append({'{#HOSTNAME}':hosthost, '{#TXTNUM}':'1'})
        senderData.append('"' + hosthost + '" dnscheck.txt[1] "NOTXT"')


print(json.dumps({"data": jsonData}, indent=4))   # print json for LLD

senderDataNStr = '\n'.join(senderData)   # items for zabbix sender separated by newlines

# pass senderDataNStr to dnscheck-send.py:
if sys.argv[1] == 'get':
    subprocess.Popen([pythonPath, senderPyPath, 'get', senderDataNStr], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)   # spawn new process and regain shell control immediately
elif sys.argv[1] == 'getverb':
    subprocess.Popen([pythonPath, senderPyPath, 'getverb', senderDataNStr])   # do not detach if in verbose mode, also skips timeout in dnscheck-send.py
else:
    print(sys.argv[0] + ": Not supported. Use 'get' or 'getverb'.")
    sys.exit(1)

