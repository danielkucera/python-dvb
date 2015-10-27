#!/usr/bin/env python

import socket
import binascii
import sys
import time
import struct
import ConfigParser
import signal

import linuxdvb
import fcntl
import ctypes

counter = {}
datas = {}
DSTs = {}

IP_PID = {}

PAT = {}
PMT = {}
CA_PIDs = {}

PMTs = []

PMTdata = {}

sock = ""

dvfd = ""
dmfd = 0
fefd = 0

mode = ""

displayStats=0

def handleSignal(signum, stack):

    global displayStats

    print 'Received:', signum
    if signum == signal.SIGUSR1:
    	loadConfig()
    if signum == signal.SIGUSR2:
	displayStats=1

def loadConfig():

    global sock
    global mode
    global dvfd
    global dmfd
    global fefd

    config = ConfigParser.ConfigParser()
    config.read(sys.argv[1])

    mode = config.get('main', 'mode')
    
    if mode == 'ip':
        MCAST_GRP = config.get('main','source_ip')
        MCAST_PORT = config.getint('main','source_port')

    
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
          sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except AttributeError:
           pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32) 
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    #    sock.close()
        sock.bind((MCAST_GRP, MCAST_PORT))
        host = socket.gethostbyname(socket.gethostname())
        sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
        sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MCAST_GRP) + socket.inet_aton(host))

	print 'Listening on ',MCAST_GRP,':',MCAST_PORT

    if mode == 'dvb':
	print 'Mode DVB'
	adapter = '/dev/dvb/adapter0/'
	fefd = open(adapter + 'frontend0', 'r+') 
	feinfo = linuxdvb.dvb_frontend_info() 
	fcntl.ioctl(fefd, linuxdvb.FE_GET_INFO, feinfo)
	print feinfo.name


	while True:

		# Tune
		pol = config.get('main','pol')
		if (pol == 'V') or (pol == 'v'):
			print 'volt', fcntl.ioctl(fefd, linuxdvb.FE_SET_VOLTAGE, linuxdvb.SEC_VOLTAGE_13) #13 - V
		else:
			print 'volt', fcntl.ioctl(fefd, linuxdvb.FE_SET_VOLTAGE, linuxdvb.SEC_VOLTAGE_18) #18 - V
	
		time.sleep(0.250)
	
		freq = config.getint('main','freq')
	
		if (freq > 11700):
			print 'tone', fcntl.ioctl(fefd, linuxdvb.FE_SET_TONE, linuxdvb.SEC_TONE_ON) # ON - 11.7 hi
			loFreq = freq - 10600
		else:
			print 'tone', fcntl.ioctl(fefd, linuxdvb.FE_SET_TONE, linuxdvb.SEC_TONE_OFF) # OFF - 11.7 hi
			loFreq = freq - 9750
	
		time.sleep(0.250)
	
		srate = config.getint('main','srate')
	
	#	dtv_prop = ctypes.POINTER(linuxdvb.dtv_property())
		dtv_prop = linuxdvb.dtv_property()
		dtv_prop.cmd = linuxdvb.DTV_DELIVERY_SYSTEM
		dtv_prop.u.data = linuxdvb.SYS_DVBS2
	
		dtv_props = linuxdvb.dtv_properties()
		dtv_props.num = 1
	#	dtv_props.props = ctypes.POINTER(dtv_prop)
	#	dtv_props.props = ctypes.cast(dtv_prop, ctypes.POINTER(ctypes.Structure))
		dtv_props.props = ctypes.pointer(dtv_prop)
		print 'props', fcntl.ioctl(fefd, linuxdvb.FE_SET_PROPERTY, dtv_props)
	
		params = linuxdvb.dvb_frontend_parameters()
		params.frequency = loFreq * 1000
		params.inversion = linuxdvb.INVERSION_AUTO
		params.u.qpsk.symbol_rate = srate * 1000
		params.u.qpsk.fec_inner = linuxdvb.FEC_AUTO
		print 'front', fcntl.ioctl(fefd, linuxdvb.FE_SET_FRONTEND, params)
	
		fcntl.ioctl(fefd, linuxdvb.FE_GET_FRONTEND, params)
		print params.u.qpsk.fec_inner

		festatus = linuxdvb.dvb_frontend_event()
		fcntl.ioctl(fefd, linuxdvb.FE_READ_STATUS, festatus)
		if festatus.status & 0x10:
			print "FE_HAS_LOCK"
			break
		else:
			print "No lock!"

	dmfd = open(adapter + 'demux0', 'r+')

	# Pes stream
	pesfilter = linuxdvb.dmx_pes_filter_params()
	pesfilter.pid = 8192
	pesfilter.input = linuxdvb.DMX_IN_FRONTEND
	pesfilter.output = linuxdvb.DMX_OUT_TS_TAP
	pesfilter.pes_type = linuxdvb.DMX_PES_OTHER
	pesfilter.flags = linuxdvb.DMX_IMMEDIATE_START
	fcntl.ioctl(dmfd, linuxdvb.DMX_SET_PES_FILTER, pesfilter)

	dvfd = open(adapter + 'dvr0', 'r')

#	while True:
#	    fcntl.ioctl(fefd, linuxdvb.FE_GET_INFO, feinfo)
#	    print feinfo.frequency
#	    packet = dvr.read(188)
#	    print len(packet)
 
    newDSTs = {}

    config = ConfigParser.ConfigParser()
    config.read(sys.argv[1])

    for section in config.sections():
	if section != 'main':
	    newDSTs[section]=config.getint(section, 'sid')

    global DSTs
    DSTs = newDSTs

    for IP in DSTs:
        datas[IP] = ""
	IP_PID[IP] = []


def readFile(filehandle, startPos, width):
    if width == 4:
        string = filehandle[startPos:startPos+4]
        if string == '':
            raise IOError
        return struct.unpack('>L',string[:4])[0]
    elif width == 2:
        string = filehandle[startPos:startPos+2]
        if string == '':
            raise IOError
        return struct.unpack('>H',string[:2])[0]
    elif width == 1:
        string = filehandle[startPos:startPos+1]
        if string == '':
            raise IOError
        return struct.unpack('>B',string[:1])[0]

def parsePATSection(filehandle, k):

    local = readFile(filehandle,k,4)
    table_id = (local>>24)
    if (table_id != 0x0):
        print 'Ooops! error in parsePATSection()!'
	raise

#    print '------- PAT Information -------'
    section_length = (local>>8)&0xFFF
#    print 'section_length = %d' %section_length

    transport_stream_id = (local&0xFF) << 8;
    local = readFile(filehandle, k+4, 4)
    transport_stream_id += (local>>24)&0xFF
    transport_stream_id = (local >> 16)
    version_number = (local>>17)&0x1F
    current_next_indicator = (local>>16)&0x1
    section_number = (local>>8)&0xFF
    last_section_number = local&0xFF;
#    print 'section_number = %d, last_section_number = %d' %(section_number, last_section_number)

    length = section_length - 4 - 5
    j = k + 8

    while (length > 0):
        local = readFile(filehandle, j, 4)
        program_number = (local >> 16)
        program_map_PID = local & 0x1FFF
#        print 'program_number = 0x%X' %program_number
        if (program_number == 0):
	     0==0
#            print 'network_PID = 0x%X' %program_map_PID
        else:
	    PAT[program_number] = program_map_PID
	    if not program_map_PID in PMTdata:
		PMTdata[program_map_PID] = ['','','','','','','','']
	    if not program_map_PID in PMTs:
		PMTs.append(program_map_PID)
#            print 'program_map_PID = 0x%X' %program_map_PID

        length = length - 4;
        j += 4
        
#        print ''


def parsePMTSection(PID):

    k = 1
    esPIDs = []

    foundFirst=0

    filehandle = ''.join(PMTdata[PID])

#    filehandle = PMTdata[PID]

#    print filehandle.encode('hex')

    while not foundFirst and len(filehandle) > k:

        local = readFile(filehandle,k,4)
        table_id = (local>>24)
    	if (table_id == 0x2):
	    foundFirst=1
	else:
	    k += 184

    if not foundFirst:
	raise

#     print "found on position ", k

#    print '------- PMT Information -------'

    section_length = (local>>8)&0xFFF
#    print 'section_length = %d' %section_length

    program_number = (local&0xFF) << 8;

    local = readFile(filehandle, k+4, 4)

    program_number += (local>>24)&0xFF
#    print 'program_number = %d' %program_number

    version_number = (local>>17)&0x1F
    current_next_indicator = (local>>16)&0x1
    section_number = (local>>8)&0xFF
    last_section_number = local&0xFF;
#    print 'section_number = %d, last_section_number = %d' %(section_number, last_section_number)

    local = readFile(filehandle, k+8, 4)

    PCR_PID = (local>>16)&0x1FFF
#    print 'PCR_PID = 0x%X' %PCR_PID
    program_info_length = (local&0xFFF)
#    print 'program_info_length = %d' %program_info_length

    n = program_info_length
    m = k + 12;

    CAs = []

    while (n>0):
        descriptor_tag = readFile(filehandle, m, 1)
        descriptor_length = readFile(filehandle, m+1, 1)
	if descriptor_tag == 9:
            CA_PID = readFile(filehandle, m+4, 2) & 0x1fff
	    CAs.append(CA_PID)
#	    print CA_PID
	    
#        print 'descriptor_tag = %d, descriptor_length = %d' %(descriptor_tag, descriptor_length)
        n -= descriptor_length + 2
        m += descriptor_length + 2

    j = k + 12 + program_info_length
    length = section_length - 4 - 9 - program_info_length

    while (length > 0):
        local1 = readFile(filehandle, j, 1)
        local2 = readFile(filehandle, j+1, 4)

        stream_type = local1;
        elementary_PID = (local2>>16)&0x1FFF
        ES_info_length = local2&0xFFF

#        print 'stream_type = 0x%X, elementary_PID = 0x%X, ES_info_length = %d' %(stream_type, elementary_PID, ES_info_length)
	if program_number in PAT:
	     esPIDs.append(elementary_PID)
#	     print "appending %s to %s", program_number,elementary_PID
        n = ES_info_length
        m = j+5;
        while (n>0):
            descriptor_tag = readFile(filehandle, m, 1)
            descriptor_length = readFile(filehandle, m+1, 1)
#            print 'descriptor_tag = %d, descriptor_length = %d' %(descriptor_tag, descriptor_length)
	    if descriptor_tag == 9:
	        CA_PID = readFile(filehandle, m+4, 2) & 0x1fff
	   	CAs.append(CA_PID)
            n -= descriptor_length + 2
            m += descriptor_length + 2


        j += 5 + ES_info_length
        length -= 5 + ES_info_length

#    print ''
    PMT[program_number]=esPIDs
    CA_PIDs[program_number]=CAs
#    print PMT
    return section_length

sendsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP

def send_to(IP, data):

  datas[IP] += data
  if (len(datas[IP]) > 1315):
      sendsock.sendto(datas[IP], (IP, 1234))
      datas[IP] = "" 
		

def main():

  signal.signal(signal.SIGUSR1, handleSignal)
  signal.signal(signal.SIGUSR2, handleSignal)

  loadConfig()

  pktCnt = 0
  scrambledCnt = 0
  CCerrors = 0
  haveStream = False
  lastTime = 0
  oldpacket = ""

  global displayStats
  data = ""

  while True:
    if mode == 'ip':
      try:
        data, addr = sock.recvfrom(1316)
      except socket.error, e:
        print 'Expection'

#    if not haveStream:
#	haveStream = True
#	print "Have stream"
    if mode == 'dvb':
      while len(data) < 188:
        data += dvfd.read(1366-len(data))
#    print data.encode("hex")

    if displayStats:
	print (float(scrambledCnt)/(pktCnt+1))*100, "% scrambled"
	print CCerrors, " CC errors"
	print counter.keys()
	print "DSTs",DSTs
	print "PAT",PAT
	print "PMT",PMT
	print "CA_PIDs",CA_PIDs
	pktCnt = 0
	scrambledCnt = 0
	lastTime = time.time()
	displayStats=0

    while len(data) >= 188:
    	pktCnt += 1
	packet = data[:188]
	data = data[188:]
	CC = readFile(packet,3,1) & 0x7
	PID = readFile(packet, 1, 2) & 0x1fff
	hasPayload = (ord(packet[3]) & 16) != 0

	if not hasPayload:
	    continue
	
	if packet == oldpacket:
	    continue

#	for IP in IP_PID:
	if False:
	    PIDs = IP_PID[IP]
	    if (PIDs == 0):
		send_to(IP, packet)
	    elif (PID in PIDs) or (PID < 32):
		send_to(IP, packet)

	if PID == 0:
	    parsePATSection(packet,5)

	if PID in PMTs:
	    PMTdata[PID][CC] = packet[4:]
 	    try:
 		parsePMTSection(PID)
 	    except:
 		print "HUPS!!"
		pass

	oldpacket = packet



if __name__ == '__main__':
  main()
