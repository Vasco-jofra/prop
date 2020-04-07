# prop
A simple rop gadget collector.

# Install
`pip install -e . --user`

# Usage
```
usage: prop [-h] [-t] [-p] [-s] [-c] binary_path

positional arguments:
  binary_path           The binary path of the file to be analyzed

optional arguments:
  -h, --help            show this help message and exit
  -t, --text_gadgets    output gadgets in text format (default)
  -p, --python_gadgets  output gadgets as a python dictionary
  -s, --silent          no gadgets output, just some info
  -c, --code            output interesting gadgets found as python functions
                        (in development)
```

# Examples
 * `prop -h`
 * `prop /bin/ls`
 * `prop --python_gadgets /bin/ls`
 * `prop --silent /bin/ls`
 * `prop --code /bin/ls`
