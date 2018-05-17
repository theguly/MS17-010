from mysmb import MYSMB
from impacket import smb, smbconnection, nt_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException
from struct import pack
import ipaddress
import sys
import signal
import Queue
import threading

'''
Script for
- check target if MS17-010 is patched or not.
- find accessible named pipe
'''

def signal_handler(signal, frame):
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

def producer(q):
    for target in ipaddress.IPv4Network(targets):
        name = threading.currentThread().getName()
        q.put(target)
    q.join()


def consume(q):
    while(True):
        name = threading.currentThread().getName()
        target = str(q.get())
        q.task_done()

        #sys.stdout.write("%s   \r" % target)
        print("%s" % target)
        #sys.stdout.flush()
        try:
            conn = MYSMB(target)
        except:
            continue
        print "==============\nIP {}".format(target)
        try:
	        conn.login(USERNAME, PASSWORD)
        except smb.SessionError as e:
	        print('Login failed: ' + nt_errors.ERROR_MESSAGES[e.error_code][0])
	        continue
        finally:
	        print('Target OS: ' + conn.get_server_os())

        tid = conn.tree_connect_andx('\\\\'+target+'\\'+'IPC$')
        conn.set_default_tid(tid)


        # test if target is vulnerable
        TRANS_PEEK_NMPIPE = 0x23
        recvPkt = conn.send_trans(pack('<H', TRANS_PEEK_NMPIPE), maxParameterCount=0xffff, maxDataCount=0x800)
        status = recvPkt.getNTStatus()
        if status == 0xC0000205:  # STATUS_INSUFF_SERVER_RESOURCES
	        sys.stdout.write("\033[1;32m")
	        print('The target is not patched')
	        sys.stdout.write("\033[1;0m")

        else:
	        print('The target is patched')
	        continue

        print('')
        print('=== Testing named pipes ===')
        for pipe_name, pipe_uuid in pipes.items():
	        try:
		        dce = conn.get_dce_rpc(pipe_name)
		        dce.connect()
		        try:
			        dce.bind(pipe_uuid, transfer_syntax=NDR64Syntax)
			        print('{}: Ok (64 bit)'.format(pipe_name))
		        except DCERPCException as e:
			        if 'transfer_syntaxes_not_supported' in str(e):
				        print('{}: Ok (32 bit)'.format(pipe_name))
			        else:
				        print('{}: Ok ({})'.format(pipe_name, str(e)))
		        dce.disconnect()
	        except smb.SessionError as e:
		        print('{}: {}'.format(pipe_name, nt_errors.ERROR_MESSAGES[e.error_code][0]))
	        except smbconnection.SessionError as e:
		        print('{}: {}'.format(pipe_name, nt_errors.ERROR_MESSAGES[e.error][0]))

        conn.disconnect_tree(tid)
        conn.logoff()
        conn.get_socket().close()

if __name__ == '__main__':
    if len(sys.argv) != 2:
	    print("{} <ip|subnet>".format(sys.argv[0]))
	    sys.exit(1)

    targets = unicode(sys.argv[1])

    threads_num = 8
    q = Queue.Queue(maxsize = threads_num)

    for i in range(threads_num):
        t = threading.Thread(name = "ConsumerThread-"+str(i), target=consume, args=(q,))
        t.start()

    #1 thread to procuce
    t = threading.Thread(name = "ProducerThread", target=producer, args=(q,))
    t.start()

    q.join()
