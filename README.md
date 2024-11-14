# DomainSpy
Bulk lookup domains using VirusTotal API and enrich with IP-API.

This script takes a `.txt` file with each domain on a separate newline as input.

Replace line 9 with your own API key for VT. The IP-API portion does not require an API key.

If the domain does not have an A record in VT, it will use another VT API lookup to grab the A record for the root domain.

This script **does not** currently have quota handling for VT API built in.

# Requirements
This script requires `python3` and the modules `requests` and `tldextract`.

```
pip3 install requests tldextract
```

# Usage

`python3 domainspy.py -i <INPUT FILE> -o <OUTPUT CSV>`

```
user@ubuntu:~/Desktop$ python3 domainspy.py 
usage: domainspy.py [-h] [-i INPUT] [-o OUTPUT]

Checks domains in bulk using VirusTotal and IP-API.
Checks domains in VirusTotal and uses the A record from VT to lookup in IP-API.
If VT has no A record data, it will use an additional VT API call to lookup the IP of the root domain.
Takes path to a .txt file with each domain on a separate newline as input. Outputs CSV.
MAKE SURE TO UPDATE THE SCRIPT WITH YOUR VIRUSTOTAL API KEY ON LINE 9.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to the text file containing a list of domains
  -o OUTPUT, --output OUTPUT
                        Path to the output CSV file
```
