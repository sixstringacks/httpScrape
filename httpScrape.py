#!python3

#import sys
import masscan, os, socket, ssl, json, tempfile, argparse

# Create temporary file
def get_temp_file():
    return (tempfile.NamedTemporaryFile(suffix=".crt",delete=True)).name

# Decode cert
def decode_cert(cert_pem, temp_cert_file):
    with open(temp_cert_file, "w") as fout:
        fout.write(cert_pem)
    try:
        return ssl._ssl._test_decode_cert(temp_cert_file)
    except Exception as e:
        print("Error decoding certificate:", e)
    finally:
        os.unlink(temp_cert_file)

# Get certificate info from host
def get_cert_info(host, port, temp_cert_file):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext()

    try:
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.connect((host, port))
        cert_der = ssl_sock.getpeercert(True)
        cert = decode_cert(ssl.DER_cert_to_PEM_cert(cert_der), temp_cert_file)
    except Exception as e:
        print("Error decoding certificate:", e)

    return(parse_cert_data(cert))

def parse_cert_data(cert_data):

    cert_data_results = {}
    
    try:
        for property in cert_data['issuer']:
            for item in property:
                if 'countryName' in item:
                    cert_data_results['ca_countryName'] = item[1]
                if 'organizationName' in item:
                    cert_data_results['ca_orgName'] = item[1]
                if 'commonName' in item:
                    cert_data_results['ca_commonName'] = item[1]
    except Exception as e:
        print("\n[*] No issuer data found for", host, ":", port, e)

    try:
        cert_data_results['notAfter'] = cert_data['notAfter']
        cert_data_results['notBefore'] = cert_data['notBefore']
    except Exception as e:
        print("\n[*] No cert expiration data found for", host, ":", port, e)

    try:
        for property in cert_data['subject']:
            for item in property:
                cert_data_results['commonName'] = item[1]
    except Exception as e:
        print("\n[*] No subject found for", host, ":", port, e)
    
    try:
        x=0
        for property in cert_data['subjectAltName']:
            cert_data_results['DNS.'+str(x)] = property[1]
            x += 1
    except Exception as e:
        print("\n[*] No subjectAltName found for", host,":", port, e)
    
    return cert_data_results
  

if __name__ == "__main__":  
    
    print('''
       __    __  __       _____                          
      / /_  / /_/ /_____ / ___/______________ _____  ___ 
     / __ \\/ __/ __/ __ \\\__ \\/ ___/ ___/ __ `/ __ \\/ _ \\
    / / / / /_/ /_/ /_/ /__/ / /__/ /  / /_/ / /_/ /  __/
   /_/ /_/\__/\__/ .___/____/\___/_/   \__,_/ .___/\___/ 
                /_/                        /_/           

    httpScrape | A tool for scraping SSL certificates
               written by @infoplague
    ''')

    parser = argparse.ArgumentParser(description="httpScrape")
    parser.add_argument("-c", "--cidr", type=str, help="cidr block to scan", default="192.168.1.0/24")
    parser.add_argument("-p", "--ports", type=str, help="https ports", default=443)
    args = parser.parse_args()
    cidr = args.cidr
    ports = args.ports

    temp_cert_file = get_temp_file()

    # use masscan to scan for lists listening on specified ports
    mas = masscan.PortScanner()
    mas.scan(cidr, str(ports))

    # extract host and port from scan results
    targets = {}

    for host in mas.scan_result['scan']:
        targets[host] = ''
    for host in targets:
        port = str(mas.scan_result['scan'][host]['tcp']).split(':')[0].split('{')[1]
        targets[host] = port

    for key,value in targets.items():
        try:
            host_name = socket.gethostbyaddr(key)
            host_name = host_name[0]
        except Exception as e:
            print("\n[!]", e,": Reverse lookup failed, using IP (", key,")")
            host_name = key

        cert_info = get_cert_info(str(host_name), int(value), temp_cert_file)
        
        print("\n[*] Results for host:", host_name, "- Port:", value)
        
        for key,value in cert_info.items():
            print(" " + key.ljust(17, "."),value)    