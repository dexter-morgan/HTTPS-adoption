import sys , re
import requests
import csv
import multiprocessing as mp

bad_sites = []

def get_headers(params):
	'''
		Takes argument a tuple 'params'
		 with protocol('http://' or 'https://') as first element 
		 and site name as second element
		Returns the list of header values(i.e whether it is set or not) and the error encountered if any
		In this order 'Input_URL','STATUS','CSP','CORS','X-Frame-Options','X-Content-Type-Options','X-XSS-Protection','HTTP-only-Cookie','Error_encountered'
	'''
	ht,name = params

	# 'head' is used to mimic a browser while sending requests for headers.
	head = {'User-Agent': "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36"}
	try:
		status_c=None
		site = ht+name

		# send a request and if a redirection happens follow that till the final one.
		# timeout is set to 60sec
		r = requests.get(site,verify = False,timeout=60 , headers = head)
		while r.url != site:
			site = r.url
			r = requests.get(site,verify = False,timeout=60 , headers = head)
		
		# retrieve the status code returned and if it is not in 2xx format then raise an Exception. 
		# Otherwise continue parsing the headers obtained and to generate the return values.
		status_c = r.status_code
		if(status_c>=300 or status_c<200):
			raise Exception('got wrong status code')
		
		header = r.headers
		csp = header.get('content-security-policy')
		if csp is None:
			csp = header.get('X-Content-Security-Policy')
		if csp is None:
			csp = header.get('X-WebKit-CSP')
		
		if csp != None:
			csp = 'Set'
		else:
			csp='Not Set'
		# cors
		cors = header.get('access-control-allow-origin')
		if cors != None:
			cors = 'Set'
		else:
			cors = 'Not Set'
		# X-Frame-Options
		xfo = header.get('X-Frame-Options')
		if xfo != None:
			if xfo.lower() == 'deny' or xfo.lower() == 'sameorigin':
				xfo = xfo.lower()
			else:
				xfo = 'None'
		else:
			xfo = 'None'

		# X-Content-Type-Options
		xco = header.get('X-Content-Type-Options')
		if xco != None:
			if xco.lower() == 'nosniff':
				xco = xco.lower()
			else:
				xco='None'
		else:
			xco='None'

		# X-XSS-Protection
		xxss = header.get('X-XSS-Protection')
		if xxss != None:
			xxss = re.split(';\s?' , xxss)[0]
			if xxss == '1':
				xxss = 'Enabled'
			else:
				xxss = 'Not Enabled'
		else:
			xxss = 'Not Enabled'

		# HTTP-only cookies
		cookie = header.get('Set-Cookie')
		if cookie != None and "httponly" in cookie.lower():
			cookie = 'Set'
		else:
			cookie = 'Not Set'

		print("completed successfully for "+str(site))

		return [site,status_c,csp,cors,xfo,xco,xxss,cookie,'None']
	except Exception as e:
		# If we get an exception in 'https://' then we try the same site again with 'http://'.
		# If we get an exception on 'http://' then return the error as it is.
		if ht=='https://':
			print('got error',e,'on https,trying http')
			return get_headers(('http://',name))
		else:
			return [site,'Error','Error','Error','Error','Error','Error','Error',str(status_c)+"  "+str(e)]


if __name__ == "__main__":
	list_of_urls=None
	outfile = None
	bad_sites_out = None

	if(len(sys.argv) < 2):
		print("Usage: python3 "+str(sys.argv[0])+" input_file_name [output_file_name]")
		exit()

	with open(sys.argv[1]) as f:
		list_of_urls = f.readlines()

	if(len(sys.argv) < 3):
		outfile = 'results.csv'
		bad_sites_out = 'bad_sites.txt'
	else:
		outfile = sys.argv[2]
		bad_sites_out = 'bad_sites_'+str(outfile)+'.txt'

	csvw = csv.writer(open(outfile, 'w'))
	csvw.writerow(['Input_URL','STATUS','CSP','CORS','X-Frame-Options','X-Content-Type-Options','X-XSS-Protection','HTTP-only-Cookie','Error_encountered'])

	# create a pool of processes with count equal to number of cpus in the system
	pool = mp.Pool(processes=mp.cpu_count())

	param1=[]
	param2=[]
	# for all sites we first check with 'https://' to see if it is available
	for site in list_of_urls:
		site = site.rstrip()
		name = site.split('://')[-1]
		param1.append('https://')
		param2.append(name)
	param_list = zip(param1,param2)
	# call the 'get_headers' function with the obtained parameter parallely and combine the results into the list 'results'.
	results = pool.map(get_headers,param_list)

	# In we get errors the we note that site in the 'bad_sites_out' file and write the correct results to the output file.
	for r in results:
		if(r[1]=='Error'):
			bad_sites.append(r[0])
			continue
		csvw.writerow(r)

	g = open(bad_sites_out,'w')
	for x in bad_sites:
		g.write(str(x)+'\n')
	g.close()
