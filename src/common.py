
import matplotlib.pyplot as plt
import numpy as np
import scipy as sp
import time

def filter_by_ip(data, ip):
    results = []
    results.extend(filter_by_field(data, 'orig_h', ip))
    results.extend(filter_by_field(data, 'resp_h', ip))
    return results

def filter_by_protocol(data, protocol):
	return filter_by_field(data, 'proto', protocol)

def filter_by_field(data, field, value):
    filtered_data = []
    for datum in data:
        if getattr(datum, field) == value:
            filtered_data.append(datum)
    return filtered_data

def get_unique_field(data, field):
    results = set()
    for datum in data:
        results.add(getattr(datum, field))
    return results

def get_unique_src_ips(data):
	return get_unique_field(data, 'orig_h')

def get_unique_dst_ips(data):
	return get_unique_field(data, 'resp_h')

def get_stats_per_dstip(data):
	results = dict()
	for datum in data:
		dst_ip = datum.resp_h
		dst_port = datum.resp_p
		proto = datum.proto
		try:
			results[dst_ip][proto]['count'] += 1
			results[dst_ip][proto]['ports'].add(dst_port)
		except KeyError:
			d = dict()
			d[proto] = {'count': 1, 'ports': set([dst_port,]) }
			results[datum.resp_h] = d
	return results

def extract_inter_timing(data):
	timestamps = [float(datum.ts) for datum in data]
	timestamps.sort()
	initial_time = timestamps[0]
	normalized_timestamps = normalize(timestamps)
	timing = []
	for t in range(0, len(normalized_timestamps), 2):
		try:
			timing.append(normalized_timestamps[t+1] - normalized_timestamps[t])
		except IndexError:
			continue
	return timing

def extract_frequencies(data, sampling_period, window_function = np.blackman):
    # data is a list of values
    # apply fourier transform

    # apply window function
    data = np.asarray([x*y for x,y in zip(data, window_function(len(data)))])

    N = len(data) # number of data points
    dt = sampling_period

    yf = np.fft.fft(data)
    #yf = np.fft.fftshift(yf)
    n = np.arange(-N/2, N/2, 1)
    freqs = np.true_divide(n, N*dt)

    plt.figure()
    plt.plot(freqs[N/2:], np.abs(yf[:N//2:]), 'o-')
    plt.xlim(0, max(freqs[N/2:]))
    plt.show()
    return (freqs[N/2:], yf.real[N/2:])

def extract_psd(data, window_size, window_overlap, window_function = np.blackman):
    return sp.signal.welch(data, sampling_freq, nperseg = window_size, noverlap = window_overlap, window = window_function)

# returns list of data sizes sent during connections
def extract_data_sizes(data):
    results = []
    omit_counter = 0
    for datum in sorted(data, key=lambda k: k.ts):
        try:
            results.append(float(datum.orig_bytes))
        except ValueError:
            results.append(0)
            omit_counter += 1
    if omit_counter:
        print "Zerod {0} items in size extraction".format(omit_counter)
	return results

def extract_times(data):
    results = []
    for datum in sorted(data, key=lambda k: k.ts):
        results.append(float(datum.ts))
    return results

def extract_items_per_n_seconds_window(data, seconds):
    sorted_data = sorted(data, key=lambda k: k.ts)
    min_time = float(sorted_data[0].ts) - (float(sorted_data[0].ts) - int(float(sorted_data[0].ts)))
    max_time = float(sorted_data[-1].ts) + (1 - (float(sorted_data[-1].ts) - int(float(sorted_data[-1].ts))))

    sizes = []
    times = []
    start = min_time
    end = start + seconds
    count = 0
    while True:
        total_size = 0
        count += 1
        if end > max_time:
            break
        for datum in data:
            if float(datum.ts) >= start and float(datum.ts) < end:
                try:
                    total_size += int(datum.orig_ip_bytes)
                except ValueError:
                    print "error"
                    continue
        times.append(start)
        sizes.append(total_size)
        start = end
        end = start + seconds

    return times, sizes

def graph_tcp_data_sizes_per_ip(data, ip):
    cip = filter_by_protocol(data, "tcp")
    sizes = extract_data_sizes(cip)
    times = extract_times(cip)
    normalized_times = normalize(times)
    graph_xy(normalized_times, sizes, 'connection-data-sizes-'+ip)

def normalize(sorted_data):
    start = sorted_data[0]
    return [i - start for i in sorted_data]

def split_by_24hr(connections):
	sorted_conns = sorted(connections, key=lambda k: k['ts'])
	connections_per_hour = []
	start = float(sorted_conns[0]['ts'])
	hour = []
	print convert_epoch_time(start)
	for conn in sorted_conns:
		if float(conn['ts']) <= (start + 86400):
			hour.append(conn)
		else:
			start = float(conn['ts'])
			print convert_epoch_time(start)
			connections_per_hour.append(hour)
			hour = []
			hour.append(conn)
	connections_per_hour.append(hour)
	return connections_per_hour


def graph_per_ip(connections):
	ips = get_unique_dst_ips(connections)
	for ip in ips:
		print ip
		ipConns = get_connections_per_dst_ip(connections, ip)
		graph(frequency_between_conn(ipConns), 'nest-therm-' + ip + '.pdf')

def graph_xy(x, y, filename):
    FORMAT = 'pdf'
    plt.bar(x,y)
    plt.xlabel('Time (seconds)')
    plt.ylabel('Payload Bytes Sent')
    plt.savefig(filename + FORMAT, format=FORMAT)
    plt.show()

def graph(data, filename):
	plt.plot(data)
	plt.xlabel('Connection Index')
	plt.ylabel('Delta Time BTW Connections')
	#plt.savefig(filename,format='pdf')
	plt.show()

def graph_multiple(dataList):
	colors = ["black", "green", "red", "blue", "yellow", "cyan", "magenta"]
	count = 0
	if len(dataList) > len(colors):
		print "Too many data sets, not enough colors"
		return 1

	for data in dataList:
		plt.bar(data, color=colors[count], label=count)
		count += 1

	#plt.plot(d1, color="black", label="54.204.245.233")
	#plt.plot(d2, color="green", label="50.16.233.36")
	#plt.plot(d3, color="red", label="54.225.188.100")
	#plt.plot(d4, color="blue", label="54.235.245.247")
	plt.xlabel('Connection Index')
	plt.ylabel('Time Delta')
	plt.show()

def get_items_for_day(conns, start_time):
	conns_for_day = []
	end_time = start_time + (60*60*24)
	for c in conns:
		if float(c.ts) >= start_time and float(c.ts) <= end_time:
			conns_for_day.append(c)
	return conns_for_day
