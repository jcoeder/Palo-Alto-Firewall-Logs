#!/bin/sh

# 'basename' (no extension) of the python script to execute
: "${PYTHON_SCRIPT_NAME? put_the_name_of_your_script_in_this_variable}"

# directory of this script
# https://stackoverflow.com/questions/59895/getting-the-source-directory-of-a-bash-script-from-within
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# directory of virtualenv
VIRTUALENV_DIR="${SCRIPT_DIR}/virtualenv"

# if 'pip' command doesn't exist, install it via yum
if ! command -v pip &> /dev/null; then
  sudo yum -y install python2-pip
fi

# if 'virtualenv' comamnd doesn't exist, install it via pip
if ! command -v virtualenv &> /dev/null; then
  sudo pip install virtualenv
fi

# if the virtualenv doesn't exist, create it
if [ ! -d "${VIRTUALENV_DIR}" ]; then
  virtualenv "${VIRTUALENV_DIR}"
fi

# activate the virtualenv
source ${VIRTUALENV_DIR}/bin/activate

# install the requirements for the script
pip install -q -r "${SCRIPT_DIR}/${PYTHON_SCRIPT_NAME}-requirements.txt"

# execute the script
${SCRIPT_DIR}/${PYTHON_SCRIPT_NAME}.py "$@"
