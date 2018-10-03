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

    NetworkItem = collections.namedtuple('NetworkItem', ' '.join(FIELDS))
    for datum in data:
        try:
            datum_dict = dict(zip(FIELDS[:-1], datum.split()))
            datum_dict['type'] = 'bro_conn'
            ni = NetworkItem(**datum_dict)
            results.append(ni)
        except Exception as e:
            print "Error parsing Bro conn", repr(e)

    return results
