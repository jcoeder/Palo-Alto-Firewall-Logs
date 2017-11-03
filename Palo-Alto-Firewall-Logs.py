#!/usr/bin/env python

# Setup instructions (tested on python 2.7):
#
# pip install virtualenv
# virtualenv -p /usr/bin/python2.7 GitHub/Palo-Alto-Firewall-Logs
# cd GitHub/Palo-Alto-Firewall-Logs
# source ./bin/activate
# pip install requests
# pip install xmltodict
#
#
# Option #2 (nick's way, automatically creates virtualenv and requirements for you):
# ./Palo-Alto-Firewall-Logs.sh -H 172.16.216.20 -U admin -P PASSWORD --query "(addr in 8.8.8.8)"
#
#
# Example usage:
#  ./Palo-Alto-Firewall-Logs.py -H 172.16.216.20 -U admin -P PASSWORD --query "(addr in 8.8.8.8)"
#  ./Palo-Alto-Firewall-Logs.py -H 172.16.216.20 -U admin -P PASSWORD --query "(url contains google.com)"
#  # read queries from CSV
#  ./Palo-Alto-Firewall-Logs.py -H 172.16.216.20 -U admin -P PASSWORD --filename ./input_data.csv

import argparse
import csv
import json
import requests
import urllib
import urllib3
import xmltodict

# silence SSL warnings
urllib3.disable_warnings()
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
        parser.add_argument('-f', '--filename', help='path to CSV query file')
        args = parser.parse_args()
        return args

class PaloAltoFirewall(object):
    def __init__(self, args):
        self.args = args
        self.username = args.username
        self.password = args.password
        self.cached_configs = {}

    def get(self, session, url):
        # send the query to the server
        response = session.get(url, verify=False)
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

    def _run_query(self, endpoint, params):
        for host in self.args.hostname:
            hostname = host
            url = "https://{0}".format(hostname)
            session = requests.Session()
            session.verify = False
            session.auth = (self.username, self.password)
            # make my query URL
            full_url = "{0}{1}".format(url, endpoint)
            result = self.get(session, full_url)
            if 'result' not in result['response']:
                print "ERROR: {}".format(json.dumps(result, indent=4))
                continue

            # extract the jobid
            job_id = result['response']['result']['job']
            # get the results of the job
            logs_result = self.get_job_results(session, url, job_id)
            # loop over each log entry

            #print json.dumps(logs_result, indent=4)
            count = logs_result['response']['result']['log']['logs']['@count']
            if count == '0':
                print "No result returned!"
                continue

            entries = logs_result['response']['result']['log']['logs']['entry']
            if not isinstance(entries, list):
                entries = [entries]

            log_data = []
            for entry in entries:
                line = ""
                log = {'firewall': hostname,
                       'query': query}
                for p in params:
                    log[p] = entry[p]
                    if p in entry:
                        line += "{}='{}' ".format(p, entry[p])
                    else:
                        line += "{}=''".format(p)
                log_data.append(log)

            return log_data

    def run_traffic(self, query):
        query = urllib.quote_plus(query)
        endpoint = "/api/?type=log&log-type=traffic&query={0}".format(query)
        params = ['src','dst', 'dport', 'proto', 'app', 'rule', 'action']
        return self._run_query(endpoint, params)

    def run_url(self, query):
        query = urllib.quote_plus(query)
        endpoint = "/api/?type=log&log-type=url&query={0}".format(query)
        params = ['src','dst', 'dport', 'proto', 'app', 'misc', 'action']
        return self._run_query(endpoint, params)

    def run_query(self, query):
        if 'url' in query:
            print "running url query"
            return self.run_url(query)
        else:
            print "running traffic query"
            return self.run_traffic(query)

    def find_config_security_rule(self, rule_name, log_group):
        firewall = log_group['firewall']
        # cache the firewall config
        if firewall not in self.cached_configs:
            ## get the entire config (lots of data)
            #endpoint = "/api/?type=config&action=show"
            # get just the security rules
            endpoint = "/api/?type=config&action=show&xpath=/config/devices/entry/vsys/entry/rulebase/security/rules"

            hostname = firewall
            url = "https://{0}".format(hostname)
            session = requests.Session()
            session.verify = False
            session.auth = (self.username, self.password)
            # make my query URL
            full_url = "{0}{1}".format(url, endpoint)
            config = self.get(session, full_url)
            #self.print_paths(result)
            self.cached_configs[firewall] = config
        else:
            config = self.cached_configs[firewall]

        ## used when we query the entire config
        #security_rules = config['response']['result']['config']['devices']['entry']['vsys']['entry']['rulebase']['security']['rules']['entry']

        ## used when we query just the security rules
        security_rules = config['response']['result']['rules']['entry']

        matching_rules = []
        for rule in security_rules:
            if rule['@name'] == rule_name:
                rule['firewall'] = firewall
                matching_rules.append(rule)

        output_rules = {'logs': log_group['logs'],
                        'rule_configs': matching_rules}
        return output_rules

    def print_paths(self, data, path=None):
        for k, v in data.items():
            if path:
                sub_path = "{}.{}".format(path, k)
            else:
                sub_path = k
            print sub_path

            if isinstance(v, dict):
                self.print_paths(v, sub_path)


if __name__ == '__main__':
    cli = Cli()
    args = cli.parse()
    client = PaloAltoFirewall(args)

    log_data = []
    if args.filename:
        with open(args.filename) as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                src_ip = row['src_ip']
                dst_ip = row['dst_ip']
                dst_port = row['dst_port']
                url = row['url']

                if not src_ip:
                    src_ip = '0.0.0.0/0'
                if not dst_ip:
                    dst_ip = '0.0.0.0/0'

                if url:
                    query = ("addr in {} and url contains {}"
                             .format(src_ip, url))
                else:
                    query = ("addr in {} and addr in {}"
                             .format(src_ip, dst_ip))

                if dst_port:
                    query += " and port.dst eq {}".format(dst_port)

                results = client.run_query('(' + query + ')')
                if results:
                    log_data.extend(results)
    else:
        results = client.run_query(args.query)
        if results:
            log_data.extend(results)

    # group all of the logs together by their rule name, so we only query once
    grouped_logs = {}
    for log in log_data:
        if log['rule'] not in grouped_logs:
            grouped_logs[log['rule']] = {'logs': [],
                                         'firewall': log['firewall']}
        grouped_logs[log['rule']]['logs'].append(log)

    # find the rule in the config for each rule that we found
    # in our logs
    output_rules = []
    for rule_name, log_group in grouped_logs.items():
        rule = client.find_config_security_rule(rule_name, log_group)
        output_rules.append(rule)

    print json.dumps(output_rules, indent=4)
