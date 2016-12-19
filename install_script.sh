#!/bin/bash

mkdir -p ~/.ipython/kernels/e3-kernel/
START_SCRIPT_PATH=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd)/e3_kernel.py
PYTHON_PATH=$(which python)
CONTENT='{
   "argv": ["'${PYTHON_PATH}'", "'${START_SCRIPT_PATH}'", "{connection_file}"],
                "display_name": "e3-kernel",
                "language": "e3"
}'
echo $CONTENT > ~/.ipython/kernels/e3-kernel/kernel.json
