# misPYgris 
Mispygris is a static malware analysis tool integrated into the MISP platform using the PYMISP API. The program operates in two modes. 

The “populate” mode extracts metadata from a binary file as well as printable strings contained within it and writes this data to a text file. 

The “query” mode uses the MISP API to search the attributes based on the previously created file. 

The objective of this project is to perform an initial triage of suspicious binaries using a local instance of MISP in order to prevent any data leaks.


<img src="avatar.jpg" alt="Alt text" style="width:50%; height:auto;">

## Download and installation
```bash
git clone https://github.com/voisina/mispygris.git
cd mispygris
python3 -m venv venv && . venv/bin/activate
pip install pymisp pefile
```

## Documentation
```bash
usage: mistigris.py [-h] [-f FILE] -m {populate,query} [-n MIN_LENGTH] [--misp-url MISP_URL] [--misp-key MISP_KEY] [--misp-cert MISP_CERT] [--ioc-file IOC_FILE]

Extract printable strings from binary files and interact with a MISP instance.

options:
  -h, --help            show this help message and exit
  -f, --file FILE       Path to a binary file
  -m, --mode {populate,query}
                        populate: store artifacts, query: check on MISP instance
  -n, --min-length MIN_LENGTH
                        Minimum string length (default: 4)
  --misp-url MISP_URL   MISP instance URL
  --misp-key MISP_KEY   MISP API key
  --misp-cert MISP_CERT
                        SSL certificate
  --ioc-file IOC_FILE   IOC input file for query mode (default: artifacts.txt)

    Examples:
      Extract strings from a single file and populate MISP:
       program.py -f sample.bin -m populate

      Read IOC from a file and query MISP:
       program.py -m query --misp-url https://misp.local --misp-key ABC123 --misp-cert cert.crt
```


## Limitations and future improvements 

