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
# Example usage:
#  ./firewall_logs.py -H 172.16.216.20 -U admin -P PASSWORD --query "(addr in 8.8.8.8)"
#  ./firewall_logs.py -H 172.16.216.20 -U admin -P PASSWORD --query "(url contains google.com)"
