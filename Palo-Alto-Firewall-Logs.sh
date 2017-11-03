#!/bin/sh

# 'basename' (no extension) of the python script to execute
PYTHON_SCRIPT_NAME="Palo-Alto-Firewall-Logs"

# directory of this script
# https://stackoverflow.com/questions/59895/getting-the-source-directory-of-a-bash-script-from-within
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# execute the script
. ${SCRIPT_DIR}/run_python_script.sh "$@"
