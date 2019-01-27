# HTTPS-adoption
Scripts to test HTTPS adoption in websites and to scan for Web vulnerabilities

Script Files

	parser.py:
		needs two arguments first is input_file_name, other is results_output_file_name
		This generates the header results into the output_file

	https.py
		After running the parser, run this file with one argument the output_file_name of parser.py
		This will update the result and add another column with HTTPS usage check.

	pyssltest.py
		Run this script with '-i input_file -o output_file'.
		This runs uses the qualys api and writes the results to the output_file
		This will also create a directory called results with the files that it receives as result from the qualys test.
		These result files are parsed to generate the output_file.

