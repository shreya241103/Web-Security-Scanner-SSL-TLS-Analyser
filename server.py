import socket
import requests
import ssl
import threading
from OpenSSL import SSL
import socket
# from zapv2 import ZAPv2
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import warnings
warnings.filterwarnings("ignore")
def web_scanner(data):
        target_url = data# a safer website 
        # try with https://example.com less safer website
        with open('demo.txt','w') as f:
            try:
                # Disable SSL certificate verification (for demonstration purposes only, not recommended for production use)
                ssl._create_default_https_context = ssl._create_unverified_context

                # Send a HEAD request to the target URL to retrieve headers
                response = requests.head(target_url)

                # Check the response status code
                if response.status_code == 200:
                    print(f"Target URL {target_url} is accessible (status code: {response.status_code}).",file=f)
                    print("-----[1] SECURITY HEADER CHECK-----------",file=f)


                    if response.headers.get('Strict-Transport-Security'):
                        print("Strict Transport Security (HSTS) header is present.",file=f)
                    else:
                        print("Strict Transport Security (HSTS) header is not  present.",file=f)
                         
                         

                    if response.headers.get('X-Content-Type-Options'):
                        print("X-Content-Type-Options header is present.",file=f)
                    else:
                        print("X-Content-Type-Options header is not present.",file=f)

                    if response.headers.get('X-XSS-Protection'):
                        print("X-XSS-Protection header is present.",file=f)
                    else :
                        print("X-XSS-Protection header is not present.",file=f)

                    if response.headers.get('X-Frame-Options'):
                        print("X-Frame-Options header is present.",file=f)
                    else :
                        print("X-Frame-Options header is not present.",file=f)
                    print("------------------------------------------",file=f)
                    # Perform further security checks or vulnerability scans here
                else:
                    print(f"Target URL {target_url} is not accessible (status code: {response.status_code}).",file=f)
                    
            except requests.exceptions.RequestException as e:
                print(f"Error occurred while making the request: {e}",file=f)




            def check_ssl_tls_configuration(website_url):
                """
                Check SSL/TLS configuration for a given website.
                """
                # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # sock.settimeout(10)

                # WRAP SOCKET
                # wrappedSocket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ADH-AES256-SHA")
                print("-----[2] SSL/TLS configuration-------------------",file=f)
                try:
                    # Create a socket
                    sock = socket.create_connection((website_url, 443))
                    sock.settimeout(10)

                    # Wrap the socket with SSL
                    ssl_sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv23)

                    # Get the SSL/TLS configuration information
                    cipher = ssl_sock.cipher()
                    
                    print("Website URL:", website_url,file=f)
                    print("Protocol Version:", ssl_sock.version(),file=f)
                    print("Cipher Suite:", cipher[0],file=f)
                    print("SSL/TLS Configuration is secure.",file=f)

                    
                    
                except ssl.SSLError as e:
                    print("Website URL:", website_url,file=f)
                    print("Error:", e,file=f)
                except Exception as e:
                    print("Error:", e,file=f)

                finally:
                    # Close the SSL socket
                    ssl_sock.close()
                    sock.close()
                print("-------------------------------------------",file=f)

            # Example usage
            website_url = target_url.replace('https://','')
            check_ssl_tls_configuration(website_url)
            website_url = target_url.replace('https://','')

            # Establish an SSL/TLS connection to the website
            context = ssl.create_default_context()
            sock = socket.create_connection((website_url, 443))
            ssl_sock = context.wrap_socket(sock, server_hostname=website_url)

            # Get the SSL/TLS certificate from the website
            certificate = ssl_sock.getpeercert(binary_form=True)
            ssl_sock.close()

            # Parse the certificate using cryptography
            cert = x509.load_der_x509_certificate(certificate, default_backend())

            # Extract certificate information
            subject = cert.subject
            issuer = cert.issuer
            serial_number = cert.serial_number
            not_valid_before = cert.not_valid_before
            not_valid_after = cert.not_valid_after

            # Print the extracted certificate information
            print("-----[3] SSL/TLS CERTIFICATE INFORMATION--------",file=f)
            print(f'Subject: {subject}',file=f)
            print(f'Issuer: {issuer}',file=f)
            print(f'Serial Number: {serial_number}',file=f)
            print(f'Not Valid Before: {not_valid_before}',file=f)
            print(f'Not Valid After: {not_valid_after}',file=f)
            print("-----------------------------------------------",file=f)

            url = target_url+'/'

            # Define a list of payloads for SQL injection testing
            sql_injection_payloads = ["' OR '1'='1", "'; DROP TABLE users;", "SELECT * FROM users WHERE username = 'admin' AND password = 'password'"]

            # Define a list of payloads for XSS testing
            xss_payloads = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(\'XSS\')">']

            # Define headers for the HTTP request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}
            print("-----[4] VULNERABILITY CHECK--------------------",file=f)
            # Test for SQL injection vulnerabilities
            for payload in sql_injection_payloads:
                payload_url = url + payload
                response = requests.get(payload_url, headers=headers)
                if "error" in response.text:
                    print(f"SQL Injection vulnerability found at: {payload_url}",file=f)

                    break
            else:
                print("No SQL Injection vulnerabilities found.",file=f)


            # Test for XSS vulnerabilities
            for payload in xss_payloads:
                payload_url = url + payload
                response = requests.get(payload_url, headers=headers)
                if payload in response.text:
                    print(f"XSS vulnerability found at: {payload_url}",file=f)

                    break
            else:
                print("No XSS vulnerabilities found.",file=f)
            print("---------------------------------------------",file=f)
            print("---------------------------------------------",file=f)

            result = subprocess.run(['nmap', website_url], stdout=subprocess.PIPE)
            print("-----[5] NMAP RESULT---------------------",file=f)
            print(f"{result.stdout.decode()}",file=f)
            f.close()


# Set up the server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('192.168.64.7', 8009))
server_socket.listen()

print("Server started. Waiting for connections...")

# Listen for incoming connections and handle them
while True:
    conn, addr = server_socket.accept()
    print("Client connected:", addr)

    # Handle the client's requests
    while True:
        # Receive the string from the client
        data = conn.recv(1024).decode()

        if not data:
            break

        # Capitalize the string and send it back to the client
        print("Message from: " + str(addr))
        print("From connected user: " + data)
        print("\n-----PROCESSING STARTED--------------------\n")
        web_scanner(data)
        server_socket.sendto(b"PROCESSING COMPLETED", addr)


    print("Client disconnected")
    conn.close()
