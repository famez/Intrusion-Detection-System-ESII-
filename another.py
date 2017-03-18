#!/usr/bin/python3
'''
Created on Mar 7, 2017

@author: famez
'''
import sys
import re
import os
import smtplib
import time,datetime
from scapy.all import *
from optparse import OptionError
from optparse import OptionGroup
from optparse import OptionParser
import Ifaddr


BROADCAST_ADDR = "10.1.1.255"
BROADCAST_MAC="ff:ff:ff:ff:ff:ff"


#Overwritten IP packet so as to get answers from broadcast addresses
class IPModified(IP):
    name = "IPMOD"
    def answers(self, other):
        val = super(IP, self).answers(other)
        if val:
            return val
        if(hasattr(self, "brdcastAddr")):
            if (other.dst == self.brdcastAddr):
                return self.payload.answers(other.payload)
        return 0
    def setBrcastAddress(self, addr):
        self.brdcastAddr = addr

class IDS():
    
    def fakeIPPacket(self):
        conf.checkIPaddr = False;
        
        #Used customize ip packet which gets broadcast responses
        split_layers(Ether, IP, type=2048)
        bind_layers( Ether, IPModified,            type=2048)
        
        #Same for ICMP
        split_layers( IP,            ICMP,          frag=0, proto=1)
        bind_layers( IPModified,            ICMP,          frag=0, proto=1)
        
    def unFakeIPPacket(self):
        conf.checkIPaddr = True;
        
        #Used customize ip packet which gets broadcast responses
        split_layers(Ether, IPModified, type=2048)
        bind_layers( Ether, IP,         type=2048)
        
        #Same for ICMP
        split_layers( IPModified, ICMP, frag=0, proto=1)
        bind_layers( IP, ICMP, frag=0, proto=1)
    
    def getBrcastDir(self, iface):
        for i in Ifaddr.get_network_interfaces():
            if i.name == iface:
                return i.brdcastAddress
        return ""
    

    def __init__(self):
        self.version = "0.1"
        self.whitelist_file = ""
        self.log = False
        self.verbose = False
        
    def detectMachines(self):
        (opts, args) = self.__handleArguments()
        print("Finished parsing options")
        if opts.macsearch and opts.ip:
            self.__detectMachinesNetwork(opts.ip)
        if opts.macadd:
            macs = opts.macadd.split(",")
            for x in macs:
                self.__writeWhitelist(x)
        if opts.macremove:
            macs = opts.macremove.split(",")
            for x in macs:
                self.__removeWhitelist(x)
        if opts.ip and opts.macsearch == False:
            print ("Detecting machines")
            self.__detectMachinesWhitelist(opts)
            
    def __startARPScan(self):
        #sr1(ARP(op=ARP.who_has, pdst='10.1.1.0/24'))
        results, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=ARP.who_has, pdst=self.opts.ip), timeout=2);
        machines={}
        for result in results:
            answer = result[1]
            machines[answer.src] = answer.psrc
            
        return machines
            
    def __startNMAPScan(self):
        srcPort = random.randint(1025,65534)
        dstPort = random.randint(0,1024)
        results, unanswered = srp(Ether(dst=getmacbyip(self.opts.ip))/IP(dst=self.opts.ip)/TCP(sport=srcPort,dport=dstPort,flags="S"),timeout=2)
        machines={}
        for result in results:
            answer = result[1]
            machines[answer[Ether].src] = answer[IP].src
        return machines
        
    def __startPINGScan(self):
        
        self.fakeIPPacket()
        
        brcastAddr = self.getBrcastDir("eth0")
        ip = IPModified(dst=brcastAddr)
        ip.setBrcastAddress(brcastAddr)
        results, unanswered = srp(Ether(dst=BROADCAST_MAC)/ip/ICMP(type='echo-request'), iface="eth0", timeout=5)
        machines={}
        for result in results:
            result[0].show()
            answer = result[1]
            answer.show()
            machines[answer[Ether].src] = answer[IPModified].src
        self.unFakeIPPacket()
        return machines
    
    scanMethods = {'ARP' : __startARPScan, 'NMAP' : __startNMAPScan, 'PING' : __startPINGScan}

    def __scanNetwork(self,ip):
        machines={}
        if self.opts.scan in self.scanMethods:
            machines = self.scanMethods[self.opts.scan](self)
        else:
            machines = self.__startARPScan()
            
        '''   
        nm = nmap.PortScanner()
        machines=nm.scan(hosts=ip, arguments='-sP') 
        return machines
        '''
        return machines

    def __detectMachinesNetwork(self,ip):
        machines = self.__scanNetwork(ip)
        for k,v in machines.items(): 
                print("-------")
                try:   
                    print (k+" --> "+v)
                except: 
                    print (k+"--> IP not detected")

    def __detectMachinesWhitelist(self,opts):
        whitelist = self.__read_file()

        alert_mac = ""
        print("Scanning network")
        machines = self.__scanNetwork(opts.ip)

        for k,v in machines['scan'].iteritems(): 
            if str(v['status']['state']) == 'up':
                #print str(v)
                try:   
                    if str(v['addresses']['mac']) in whitelist:
                        msg = 'Mac find '+str(v['addresses']['mac'])+' Ip: '+str(v['addresses']['ipv4'])
                        if self.verbose:
                            self.__consoleMessage(msg)
                        if self.log:
                            self.__writeLog(msg)
                    else:
                        alert_mac = alert_mac+'New mac detected '+str(v['addresses']['mac'])+' Ip: '+str(v['addresses']['ipv4'])+'\n'
                        msg = 'New mac detected '+str(v['addresses']['mac'])+' Ip: '+str(v['addresses']['ipv4'])
                        if self.verbose:
                            self.__consoleMessage(msg)                        
                        if self.log:
                            self.__writeLog(msg)

                except: 
                    msg = 'Mac not detected '+str(v['addresses']['ipv4'])
                    if self.verbose:
                        self.__consoleMessage(msg)                        
                    if self.log:
                        self.__writeLog(msg)
        if opts.emailto:
            self.__sendEmail(alert_mac,opts)



    def __handleArguments(self,argv=None):
        """
        This function parses the command line parameters and arguments
        """

        parser = OptionParser()
        if not argv:
            argv = sys.argv

        mac = OptionGroup(parser, "Mac", "At least one of these "
            "options has to be provided to define the machines")

        mac.add_option('--ms','--macsearch', action='store_true', default=False, dest='macsearch', help='Search machine Network')
        mac.add_option('--ma','--macadd', action='store', dest='macadd', help='Add mac to whitelist')
        mac.add_option('--mr','--macremove', action='store', dest='macremove', help='Remove mac from whitelist')


        email = OptionGroup(parser, "Email", "You need user,password,server and destination"
            "options has to be provided to define the server send mail")

        email.add_option('-u','--user', action='store', dest='user', help='User mail server')
        email.add_option('--pwd','--password', action='store', dest='password', help='Password mail server')
        email.add_option('-s','--server', action='store', dest='server', help='mail server')
        email.add_option('-p','--port', action='store', default='25', dest='port', help='Port mail server')
        email.add_option('--et','--emailto', action='store', dest='emailto', help='Destination E-mail')
        
        scan = OptionGroup(parser, "Scan Parameters", "Scan type can be ARP method, NMAP method or PING method")
        scan.add_option('--sc','--scan', action='store', dest='scan', help='Scan type. Can be ARP, NMAP or PING')
        scan.add_option('-t','--timeout', action='store', dest='timeout', help='Scan timeout')

        parser.add_option('-r','--range', action='store', dest='ip', help='Secure network range ')
        parser.add_option('--wl','--whitelist', action='store', default='whitelist.txt' , dest='whitelist_file', help='File have Mac whitelist ')
        parser.add_option('-l','--log', action='store_true', default=False, dest='log', help='Log actions script')
        parser.add_option('-v','--verbose', action='store_true', default=False, dest='verbose', help='Verbose actions script')


        parser.add_option_group(mac)
        parser.add_option_group(email)
        parser.add_option_group(scan)

        (opts, args) = parser.parse_args()

        self.log = opts.log
        self.verbose = opts.verbose
        self.whitelist_file = opts.whitelist_file

        if opts.user or opts.password or opts.server or opts.emailto:
            if not all([opts.user, opts.password,opts.server,opts.emailto]):
                errMsg = "missing some email option (-u, --pwd, -s, --et), use -h for help"                
                parser.error(errMsg)
                self.__writeLog(errMsg)
                sys.exit(-1)
        if opts.macsearch and not opts.ip:
            errMsg = "missing some range scan option (-r), use -h for help"
            parser.error(errMsg)
            self.__writeLog(errMsg)
            sys.exit(-1)
            
        self.opts = opts;
        return opts, args


    def __sendEmail(self,alert_mac,opts):
        """
        This function send mail with the report
        """
        header  = 'From: %s\n' % opts.user
        header += 'To: %s\n' % opts.emailto
        if alert_mac:
            header += 'Subject: New machines connected\n\n'
            message = header + 'List macs: \n '+str(alert_mac)
        else:
            header += 'Subject: No intruders - All machines known \n\n'
            message = header + 'No intruders'

        server = smtplib.SMTP(opts.server+":"+opts.port)
        server.starttls()
        server.login(opts.user,opts.password)
        if self.verbose or self.log:
            debugemail = server.set_debuglevel(1)
            if self.verbose:
                self.__consoleMessage(debugemail)
        problems = server.sendmail(opts.user, opts.emailto, message)
        print (problems)
        server.quit()


    def __consoleMessage(self,message):
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        print ('['+st+'] '+str(message))


    def __writeLog(self,log):
        """
        This function write log
        """
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        if os.path.isfile('log.txt'):
            try:
                file_read = open('log.txt', 'a')
                file_read.write('['+st+'] '+log+"\n")
                file_read.close()
            except IOError:
                msg = 'ERROR: Cannot open'+ self.whitelist_file
                if self.verbose:
                    self.__consoleMessage(msg)
                sys.exit(-1)
        else:
            msg = "ERROR: The Whitelist file ", self.whitelist_file, " doesn't exist!"
            if self.verbose:
                self.__consoleMessage(msg)
            sys.exit(-1)


    def __writeWhitelist(self,mac):
        """
        This function add newmac to whitelist
        """
        if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
            if os.path.isfile(self.whitelist_file):
                try:
                    file_read = open(self.whitelist_file, 'a')
                    file_read.write(mac+"\n")
                    file_read.close()
                    msg = "Mac: "+ mac + " add correctly"
                    if self.verbose:
                        self.__consoleMessage(msg)
                    if self.log:
                        self.__writeLog(msg) 
                except IOError:
                    print 
                    msg = 'ERROR: Cannot open'+ self.whitelist_file
                    if self.verbose:
                        self.__consoleMessage(msg)
                    if self.log:
                        self.__writeLog(msg) 
                    sys.exit(-1)
            else:
                msg = "ERROR: The Whitelist file "+ self.whitelist_file+ " doesn't exist!"
                if self.verbose:
                    self.__consoleMessage(msg)
                if self.log:
                    self.__writeLog(msg) 
                sys.exit(-1)
        else:
            msg = "ERROR: The Mac "+ mac +" not valid!"
            if self.verbose:
                self.__consoleMessage(msg)
            if self.log:
                self.__writeLog(msg) 

    def __removeWhitelist(self,mac):
        """
        This function remove newmac from whitelist
        """
        if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
            if os.path.isfile(self.whitelist_file):
                try:
                    file_read = open(self.whitelist_file, 'r')
                    lines = file_read.readlines()
                    file_read.close()
                    file_read = open(self.whitelist_file, 'w')
                    for line in lines:
                        if line.strip() != mac:
                            file_read.write(line)
                    file_read.close()
                    msg = "Mac "+mac+" remove correctly"
                    if self.verbose:
                        self.__consoleMessage(msg)
                    if self.log:
                        self.__writeLog(msg) 
                except IOError:
                    msg = 'ERROR: Cannot open '+ self.whitelist_file
                    if self.verbose:
                        self.__consoleMessage(msg)
                    if self.log:
                        self.__writeLog(msg) 
                    sys.exit(-1)
            else:
                msg = "ERROR: The Whitelist file "+ self.whitelist_file+ " doesn't exist!"
                if self.verbose:
                    self.__consoleMessage(msg)
                if self.log:
                    self.__writeLog(msg) 
                sys.exit(-1)
        else:
            msg = "ERROR: The Mac "+ mac + " doesn't exist!"
            if self.verbose:
                self.__consoleMessage(msg)
            if self.log:
                self.__writeLog(msg) 

    def __read_file(self):
        """
        This function read the whitelist
        """
        whitelist = []
        if os.path.isfile(self.whitelist_file):
            try:
                file_read = open(self.whitelist_file, 'r')
                for line in file_read:
                    if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", line.strip().lower()):
                            whitelist.append(line.strip())
                return whitelist
            except IOError:
                msg = 'ERROR: Cannot open '+ self.whitelist_file
                if self.verbose:
                    self.__consoleMessage(msg)
                if self.log:
                    self.__writeLog(msg) 
                sys.exit(-1)
        else:
            msg = "ERROR: The Whitelist file "+ self.whitelist_file+ " doesn't exist!"
            if self.verbose:
                self.__consoleMessage(msg)
            if self.log:
                self.__writeLog(msg) 
            sys.exit(-1)

if __name__ == '__main__':
    packets = []
    for i in range(0, 256):
        ip = IP(dst="10.192.1." + str(i))
        packets.append(Ether()/ip/ICMP(type='echo-request'))
        
    results, unanswered = srp(packets, iface="eth0", timeout=1)
    for result in results:
        if result[1][ICMP].type == 0:
            print ("IP " + result[1][IP].src + " detected")
