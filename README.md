# prop
A simple rop gadget collector.

# Install
`pip install -e . --user`

# Usage
```
usage: prop [-h] [-d DEPTH] [-t] [-c] [-p] [-m MAX_ADDRS_PER_GADGET] [-s] binary_path

positional arguments:
  binary_path           The binary path of the file to be analyzed

optional arguments:
  -h, --help               show this help message and exit
  -d DEPTH, --depth DEPTH  Gadget search depth (default=10)
  -t, --text_gadgets       output gadgets in text format (default)
  -c, --code               output interesting gadgets found as python functions
  -p, --python_gadgets     output gadgets as a python dictionary
  -s, --silent             no gadgets output, just some info
  -m MAX_ADDRS_PER_GADGET, --max_addrs_per_gadget MAX_ADDRS_PER_GADGET
                           the maximum number of addresses that are printed per
                           gadget (default=3)
```

# Examples
 * `prop -h`
 * `prop /bin/ls`
 * `prop --python_gadgets /bin/ls`
 * `prop --silent /bin/ls`
 * `prop --code /bin/ls`
