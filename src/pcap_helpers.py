

from scapy.all import *

import datetime
import collections

fields = [ "ts","uid","orig_h","orig_p","resp_h","resp_p","proto","service","duration","orig_bytes","resp_bytes","conn_state","local_orig","local_resp","missed_bytes","history","orig_pkts","orig_ip_bytes","resp_pkys","resp_ip_bytes","tunnel_parents"]

def read_pcap(filename):
	return rdpcap(filename)

def parse_packets(packets):
	Packet = collections.namedtuple('Packet', ' '.join(fields))
	pkts = []

	for p in packets:
		if IP in p:
			try:
				srcIp = p[IP].src
				dstIp = p[IP].dst
				size = p[IP].len

				if TCP in p:
					sport = p[TCP].sport
					dport = p[TCP].dport
				elif UDP in p:
					sport = p[UDP].sport
					dport = p[UDP].dport
				else:
					sport = None
					dport = None				

				pkt = Packet(
					ts = float(p.ts),\
					uid = None,\
					orig_h = srcIp,\
					orig_p = sport,\
					resp_h = dstIp,\
					resp_p = dport,\
					proto = 'unknown',\
					service = 'unknown',\
					duration = 0,\
					orig_bytes = len(p[IP].payload),\
					resp_bytes = None,\
					conn_state = None,\
					local_orig = None,\
					local_resp = None,\
					missed_bytes = 0,\
					history = None,\
					orig_pkts = 1,\
					orig_ip_bytes = len(p[IP].payload),\
					resp_pkys = None,\
					resp_ip_bytes = None,\
					tunnel_parents = None,\
				)
				pkts.append(pkt)
			except Exception as e:
				print "Error parsing packets", repr(e)

	return pkts

def filter_src_ip(packets, src):
	fpackets = []
	for p in packets:
		if p.srcIP == src:
			fpackets.append(p)
	return fpackets

def filter_dst_ip(packets, dst):
	fpackets = []
	for p in packets:
		if p.dstIP == dst:
			fpackets.append(p)
	return fpackets

def filter_ntp(packets):
	ntp = []
	for p in packets:
		if p.dstPort == 123:
			ntp.append(p)
	return ntp

def filter_dns(packets):
	dns = []
	for p in packets:
		if p.dstPort == 53:
			dns.append(p)
	return dns

def filter_ssl(packets):
	ssl = []
	for p in packets:
		if p.dstPort == 443:
			ssl.append(p)
	return ssl

def filter_weekdays(packets):
	weekday = []
	for p in packets:
		day = datetime.datetime.fromtimestamp(p.ts).weekday()
		if day in [0,1,2,3,4]:
			weekday.append(p)
	return weekday

def remove_zero_len_tcp(packets):
	filtered = []
	for p in packets:
		if TCP in p:
			if not len(p[TCP].payload) == 0:
				filtered.append(p)
	return filtered

def remove_dhcp(packets):
	filtered = []
	for p in packets:
		if not DHCP in p:
			filtered.append(p)
	return filtered

def remove_icmp(packets):
	filtered = []
	for p in packets:
		if not IPv6ExtHdrHopByHop in p and not ICMP in p:
			#if not p[IPv6ExtHdrHopByHop].nh == 58:
			filtered.append(p)
	return filtered

def remove_eapol(packets):
	filtered = []
	for p in packets:
		if not EAPOL in p:
			filtered.append(p)
	return filtered

def filter_time_of_day(packets, day, start, end):
	
	in_range = []
	out_range = []

	for p in packets:
		if p.ts > start and p.ts < end:
			in_range.append(p)
		else:
			out_range.append(p)

	return in_range, out_range

def get_packets_for_day(packets, start):
	duration = 60*60*24
	day = []
	for p in packets:
		if p.ts >= start and p.ts <= (start + duration):
			day.append(p)
	return day
