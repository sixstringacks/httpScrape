httpScrape is based somewhat on [sslScrape](https://github.com/cheetz/sslScrape) written by Peter Kim. I was having lots of problems trying to get sslScrape to decode self-signed certs so I rewrote it.

sudo python3 ./httpScrape.py -h

```
       __    __  __       _____                          
      / /_  / /_/ /_____ / ___/______________ _____  ___ 
     / __ \/ __/ __/ __ \\__ \/ ___/ ___/ __ `/ __ \/ _ \
    / / / / /_/ /_/ /_/ /__/ / /__/ /  / /_/ / /_/ /  __/
   /_/ /_/\__/\__/ .___/____/\___/_/   \__,_/ .___/\___/ 
                /_/                        /_/           

    httpScrape | A tool for scraping SSL certificates
               written by @autocowrekt
    
usage: httpScrape.py [-h] [-c CIDR] [-p PORTS]

httpScrape

optional arguments:
  -h, --help            show this help message and exit
  -c CIDR, --cidr CIDR  cidr block to scan
  -p PORTS, --ports PORTS  ports

```

Requirements:
pip install python-masscan
