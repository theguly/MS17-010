from mysmb import MYSMB
from impacket import smb, smbconnection, nt_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException
from struct import pack
from colorama import Fore, Back, Style
import ipaddress
import sys
import signal
import Queue
import threading
import time
import socket


'''
Script for
- check target if MS17-010 is patched or not.
- find accessible named pipe
'''

#!/usr/bin/env python
def signal_handler(sig, frame):
        print('You pressed Ctrl+C!')
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

USERNAME = ''
PASSWORD = ''

NDR64Syntax = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

MSRPC_UUID_BROWSER  = uuidtup_to_bin(('6BFFD098-A112-3610-9833-012892020162','0.0'))
MSRPC_UUID_SPOOLSS  = uuidtup_to_bin(('12345678-1234-ABCD-EF00-0123456789AB','1.0'))
MSRPC_UUID_NETLOGON = uuidtup_to_bin(('12345678-1234-ABCD-EF00-01234567CFFB','1.0'))
MSRPC_UUID_LSARPC   = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0'))
MSRPC_UUID_SAMR     = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC','1.0'))

pipes = {
	'browser'  : MSRPC_UUID_BROWSER,
	'spoolss'  : MSRPC_UUID_SPOOLSS,
	'netlogon' : MSRPC_UUID_NETLOGON,
	'lsarpc'   : MSRPC_UUID_LSARPC,
	'samr'     : MSRPC_UUID_SAMR,
}




def consume(q):
    while(True):
      target = str(q.get())
      res = "%s\t" % target
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      # Check if 445 is open
      if sock.connect_ex((target,445))==0:

	# Try to create a SMB connection
	try:
            conn = MYSMB(target)
        except:
	    res+="\n"
	    print res,
  	    q.task_done()
            continue

	# Try to authenticate
  	try:
	    conn.login(USERNAME, PASSWORD)
        except smb.SessionError as e:
	    res+="\n"
	    print res,
            q.task_done()
	    continue
        finally:
	    s = conn.get_server_os()
            i = 0
            while i<40:
		if i<len(s):
			res+=s[i]
		else:
			res+=" "
		i+=1
	    res += "\t"
	
	try:
            tid = conn.tree_connect_andx('\\\\'+target+'\\'+'IPC$')
            conn.set_default_tid(tid)

            # test if target is vulnerable
            TRANS_PEEK_NMPIPE = 0x23
            recvPkt = conn.send_trans(pack('<H', TRANS_PEEK_NMPIPE), maxParameterCount=0xffff, maxDataCount=0x800)
            status = recvPkt.getNTStatus()
            if status == 0xC0000205:  # STATUS_INSUFF_SERVER_RESOURCES
	        res +=  "NOT patched\t"

            else:
		res += "patched"
		res=Style.BRIGHT+Fore.BLUE+res+Style.RESET_ALL+"\n"
		print res,
                q.task_done()
	        continue

	except:
            res+="\n"
	    print res,
            q.task_done()
	    continue
	found = False
        for pipe_name, pipe_uuid in pipes.items():
	        try:
		        dce = conn.get_dce_rpc(pipe_name)
		        dce.connect()
		        try:
			        dce.bind(pipe_uuid, transfer_syntax=NDR64Syntax)
			        res += '{}: Ok (64 bit)\t'.format(pipe_name)
				found = True
		        except DCERPCException as e:
			        if 'transfer_syntaxes_not_supported' in str(e):
				        res+='{}: Ok (32 bit)\t'.format(pipe_name)
					found = True
			        else:
				        res+='{}: Ok ({})\t'.format(pipe_name, str(e))
					found = True
		        dce.disconnect()
	        except smb.SessionError as e:
		        res+='{}: {}\t'.format(pipe_name, nt_errors.ERROR_MESSAGES[e.error_code][0])
	        except smbconnection.SessionError as e:
		        res+='{}: {}\t'.format(pipe_name, nt_errors.ERROR_MESSAGES[e.error][0])
	
	try:
	  conn.disconnect_tree(tid)
	  conn.logoff()
          conn.get_socket().close()
	except:
	  res=Fore.YELLOW+res+Style.RESET_ALL+"\n"
	  print res,
          q.task_done()
	  continue
	if not found:
          res=Fore.YELLOW+res+Style.RESET_ALL+"\n"
          print res,
          q.task_done()
          continue

        res=Fore.RED+res+Style.RESET_ALL
     
      res+="\n"
      print res,
      q.task_done()


if __name__ == '__main__':
    # Parameters check
    if len(sys.argv) != 2:
	    print("{} <ip|subnet|filename>".format(sys.argv[0]))
	    sys.exit(1)
    ok=False
    targets = unicode(sys.argv[1])
    tgtlist=[]
    try:
	netw=ipaddress.IPv4Network(targets)
	for ip in netw:
	    tgtlist.append(ip)
	ok=True
    except:
        pass
    if not ok:
	try:
	    netlist = open(targets,'r').read().splitlines()
	    for net in netlist:
		net=net.replace("\n","").replace("\r","")
		netw=ipaddress.IPv4Network(unicode(net))
	        for ip in netw:
        	    tgtlist.append(ip)
	    ok=True
	except:
	    pass
    if not ok:
	print("Please check target!")
	sys.exit()
    cnt=len(tgtlist)    
    print("Targets: "+str(cnt))

    # Multithread  
    # Fill producer
    threads_num = 32
    if cnt<threads_num:
	threads_num=cnt
    q = Queue.Queue(maxsize = threads_num)
    for i in range(threads_num):
       t = threading.Thread(target=consume,args=(q,))
       t.daemon = True
       t.start()

    # Start consumer
    i = 0
    while i<cnt:
      thr = 0
      while i<cnt and thr<threads_num:
        q.put(tgtlist[i])
	thr+=1
	i+=1
      q.join()

