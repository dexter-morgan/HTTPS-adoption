import csv,sys

new_rows = []
heading = None

# Read the results and check if HTTPS is available and update the results file with a new column.

with open(sys.argv[1], 'r') as csvfile:
	results = csv.reader(csvfile, delimiter=',')
	for row in results:
		if(heading is None):
			if('HTTPS Usage' in row):
				exit()
			row.insert(1,'HTTPS Usage')
			heading = row
		else:
			url = row[0]
			if(row[1]=='Error'):
				continue
			elif(url.split('://')[0]=='http'):
				row.insert(1,'N')
			else:
				row.insert(1,'Y')
			new_rows.append(row)
csvw = csv.writer(open(sys.argv[1], 'w'))
csvw.writerow(heading)
for row in new_rows:
	csvw.writerow(row)


