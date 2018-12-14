#!/usr/bin/env python

# Helps read and process Bro connection logs (conn.log)

import collections

from globals import FIELDS

def read_bro_conn(conn_file, start_line = 8, end_line = -1):
	with open(conn_file, 'r') as f:
		return f.readlines()[start_line:end_line]

def parse_bro(filename):
	results = []
	data = read_bro_conn(filename)
	if not data:
		return results

	bro_conn_fields = [ "ts","uid","orig_h","orig_p","resp_h","resp_p","proto","service","duration","orig_bytes","resp_bytes","conn_state","local_orig","local_resp","missed_bytes","history","orig_pkts","orig_ip_bytes","resp_pkys","resp_ip_bytes","tunnel_parents","type"]

	NetworkItem = collections.namedtuple('NetworkItem', ' '.join(FIELDS))
	for datum in data:
		try:
			datum_dict = dict(zip(bro_conn_fields[:-1], datum.split()))
			datum_dict['type'] = 'bro_conn'
			datum_dict['orig_m'] = None
			datum_dict['resp_m'] = None
			ni = NetworkItem(**datum_dict)
			results.append(ni)
		except Exception as e:
			print 'Error parsing Bro conn', repr(e)

	return results
