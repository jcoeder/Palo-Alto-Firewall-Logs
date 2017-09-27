#!/usr/bin/env python
#
# Setup instructions (tested on python 2.7):
#
# pip install virtualenv
# virtualenv venv
# source ./venv/bin/activate
# pip install requests
# pip install xmltodict
#
#
# Example usage:
#  ./firewall_logs.py -H 172.16.216.20 -U admin -P PASSWORD --query "(addr in 8.8.8.8)"

import argparse
import json
import requests
import urllib
import xmltodict

# silence SSL warnings

requests.packages.urllib3.disable_warnings()

class Cli:
    def parse(self):
        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        # connection args
        parser.add_argument('-H', '--hostname', nargs='+', help='Hostname of firewall')
        parser.add_argument('-U', '--username', help='Username for firewall')
        parser.add_argument('-P', '--password', help='Password for firewall')
        parser.add_argument('-q', '--query', help='query for the firewall logs')
        args = parser.parse_args()
        return args

class PaloAltoFirewall(object):
    def __init__(self, args):
        self.args = args
        self.username = args.username
        self.password = args.password

    def get(self, session, url):
        # send the query to the server
        response = session.get(url)
        response.raise_for_status()
        # parse the respose from XML into a "dict"
        xml = response.content
        #print xml
        return xmltodict.parse(xml)

    def get_job_results(self, session, url, job_id):
        # make the query URL
        full_url = "{0}/api/?type=log&action=get&job-id={1}".format(url, job_id)
        results_dict = self.get(session, full_url)
        return results_dict

    def run_query(self, endpoint, params):
        for host in self.args.hostname:
            hostname = host
            url = "https://{0}".format(hostname)
            session = requests.Session()
            session.verify = False
            session.auth = (self.username, self.password)
            # make my query URL
            full_url = "{0}{1}".format(url, endpoint)
            result = self.get(session, full_url)
            # extract the jobid
            job_id = result['response']['result']['job']
            # get the results of the job
            logs_result = self.get_job_results(session, url, job_id)
            # loop over each log entry
            
            #print json.dumps(logs_result, indent=4)
            count = logs_result['response']['result']['log']['logs']['@count']
            if count == '0':
                continue

            entries = logs_result['response']['result']['log']['logs']['entry']
            if not isinstance(entries, list):
                entries = [entries] 
            for entry in entries:
                line = ""
                for p in params:17
                    if p in entry:
                        line += "{}='{}' ".format(p, entry[p])
                    else:
                        line += "{}=''".format(p)
                print (line)

    def run_traffic(self):
        query = urllib.quote_plus(self.args.query)
        endpoint = "/api/?type=log&log-type=traffic&query={0}".format(query)
        params = ['src','dst', 'dport', 'proto', 'app', 'rule', 'action']
        self.run_query(endpoint, params)

    def run_url(self):
        query = urllib.quote_plus(self.args.query)
        endpoint = "/api/?type=log&log-type=url&query={0}".format(query)
        params = ['src','dst', 'dport', 'proto', 'app', 'misc', 'action']
        self.run_query(endpoint, params)

if __name__ == '__main__':
    cli = Cli()
    args = cli.parse()
    client = PaloAltoFirewall(args)
    if 'url' in args.query:
        client.run_url()
    else:
        client.run_traffic()