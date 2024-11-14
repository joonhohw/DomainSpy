import sys
import argparse
import requests
import json
import time
import csv
import tldextract

api_key = "YOUR API KEY HERE"

vt_headers = {
	'x-apikey': api_key,
	'accept': 'application/json'
}

def check_vt_domain(domain):
	vt_result = [domain]
	vt_response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=vt_headers)
	data = json.loads(vt_response.text)
	
	if vt_response.status_code == 200:
		attributes = data['data']['attributes']
		vt_ip = ""
		
		for i in range(len(attributes['last_dns_records'])):
			if attributes['last_dns_records'][i]['type'] == 'A':
				vt_ip = attributes['last_dns_records'][i]['value']
				break
		
		if vt_ip == "":
			extracted = tldextract.extract(domain)
			rootdomain = '{}.{}'.format(extracted.domain, extracted.suffix)
			
			vt_rootdomain_response = requests.get(f"https://www.virustotal.com/api/v3/domains/{rootdomain}", headers=vt_headers)
			rootdomain_data = json.loads(vt_rootdomain_response.text)
	
			if vt_rootdomain_response.status_code == 200:
				rootdomain_attributes = rootdomain_data['data']['attributes']
				
				for i in range(len(rootdomain_attributes['last_dns_records'])):
					if rootdomain_attributes['last_dns_records'][i]['type'] == 'A':
						vt_ip = rootdomain_attributes['last_dns_records'][i]['value']
						break
		
		vt_result.append(vt_ip)
		vt_result.append(attributes['last_analysis_stats']['harmless'])
		vt_result.append(attributes['last_analysis_stats']['malicious'])
		vt_result.append(attributes['creation_date'])
		vt_result.append(attributes['last_analysis_date'])
		
		print(f"VirusTotal lookup for {domain} successful.")
	
	else:
		print(f"VirusTotal error for domain {domain}. Status code: {vt_response.status_code}. Message: {data['error']['message']}")
		
	return vt_result
	
def check_ipapi(ip):

	if ip == "":
		return

	ia_return = []
	ia_result = []
	ia_response = requests.get(f"http://ip-api.com/json/{ip}?fields=16780825")
	limit = int(ia_response.headers['X-Rl'])
	timeout = int(ia_response.headers['X-Ttl']) + 1
	data = json.loads(ia_response.text)
	
	if ia_response.status_code == 200:
		ia_result.append(data['country'])
		ia_result.append(data['regionName'])
		ia_result.append(data['city'])
		ia_result.append(data['isp'])
		ia_result.append(data['org'])
		ia_result.append(data['as'])
		ia_result.append(data['hosting'])
		
		ia_return.append(ia_result)
		ia_return.append(limit)
		ia_return.append(timeout)
		
		print(f"IP-API lookup for {ip} successful.")
	
	else:
		print(f"IP-API error for ip {ip}. Status code: {ia_response.status_code}.")
	
	return ia_return
	
def main():
	parser = argparse.ArgumentParser(description = "Checks domains in bulk using VirusTotal and IP-API.\nChecks domains in VirusTotal and uses the A record from VT to lookup in IP-API.\nIf VT has no A record data, it will use an additional VT API call to lookup the IP of the root domain.\nTakes path to a .txt file with each domain on a separate newline as input. Outputs CSV.\nMAKE SURE TO UPDATE THE SCRIPT WITH YOUR VIRUSTOTAL API KEY ON LINE 9.", formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-i', '--input', type=str, help="Path to the text file containing a list of domains")
	parser.add_argument('-o', '--output', type=str, help="Path to the output CSV file")
	
	if len(sys.argv) == 1:
		parser.print_help(sys.stderr)
		sys.exit(1)
	
	args = parser.parse_args()
	
	i_file = args.input
	o_file = args.output
	
	ia_limit = 45
	ia_timeout = 60
	
	with open(i_file, 'r') as file:
		domain_list_raw = file.read().splitlines()
		domain_list = [x for x in domain_list_raw if x.strip()]
	
	with open(o_file, 'a', newline='') as file:
		writer = csv.writer(file)
		writer.writerow(["domain", "ip", "harmless", "malicious", "creation_date", "last_analysis_date", "country", "region", "city", "isp", "org", "as", "hosting"])
		
		for domain in domain_list:
			vt = check_vt_domain(domain)
			
			if not ia_limit > 0:
				print(f"IP-API about to rate limit. Waiting {ia_timeout} seconds...")
				time.sleep(ia_timeout)

			ia_list = check_ipapi(vt[1])
			
			if ia_list:
				ia = ia_list[0]
				ia_limit = ia_list[1]
				ia_timeout = ia_list[2]
				
				vt.extend(ia)
			
			writer.writerow(vt)

if __name__ == '__main__':
	main()
	
