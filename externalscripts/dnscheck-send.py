#!/usr/bin/env python3

senderPath = r'zabbix_sender'
#senderPath = r'/usr/local/bin/zabbix_sender'   # if zabbix sender isn't in PATH
serverIP = '192.0.2.2'
timeout = 60   # how long the script must wait between LLD and sending, increase if data received late

## End of configuration ##

import sys
import subprocess
from time import sleep

senderDataNStr = sys.argv[2]

if sys.argv[1] == 'get':
    sleep(timeout)   # wait for LLD to be processed by server
    senderProc = subprocess.Popen([senderPath, '-z', serverIP, '-i', '-'], stdin=subprocess.PIPE, universal_newlines=True)   # send data gathered from second argument to zabbix server
elif sys.argv[1] == 'getverb':
    print('\n  Data sent to zabbix sender:\n' + senderDataNStr)
    sys.stdout.flush()   # print before proc results
    senderProc = subprocess.Popen([senderPath, '-vv', '-z', serverIP, '-i', '-'], stdin=subprocess.PIPE, universal_newlines=True)   # verbose sender output
    print('\n  Note: the sender will fail if server did not gather LLD previously.')
else:
    print(sys.argv[0] + ": Not supported. Use 'get' or 'getverb'.")
    sys.exit(1)

senderProc.communicate(input=senderDataNStr)

