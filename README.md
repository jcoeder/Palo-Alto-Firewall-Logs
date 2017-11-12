# Setup instructions (tested on python 2.7):
#
# pip install virtualenv
# virtualenv -p /usr/bin/python2.7 GitHub/Palo-Alto-Firewall-Logs
# cd GitHub/Palo-Alto-Firewall-Logs
# source ./bin/activate
# pip install requests
# pip install xmltodict
#
# On a Mac (OSX):
# sudo python -m pip install "requests[security]"
# sudo python3 -m pip install "requests[security]"
#
# Example usage:
#  ./Palo-Alto-Firewall-Logs.py -H 172.16.216.20 -U admin -P PASSWORD --query "(addr in 8.8.8.8)"
#  ./Palo-Alto-Firewall-Logs.py -H 172.16.216.20 -U admin -P PASSWORD --query "(url contains google.com)"
#  # read queries from CSV
#  ./Palo-Alto-Firewall-Logs.py -H 172.16.216.20 -U admin -P PASSWORD --filename ./input_data.csv
#
# Option #2 (Nick's way, automatically creates virtualenv and requirements for you):
# ./Palo-Alto-Firewall-Logs.sh -H 172.16.216.20 -U admin -P PASSWORD --query "(addr in 8.8.8.8)"
