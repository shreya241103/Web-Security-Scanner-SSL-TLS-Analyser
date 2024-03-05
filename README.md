The project aims to provide insights into the security vulnerabilities and configurations of web applications. The program conducts various checks, including:

1. Security header analysis, such as Strict Transport Security (HSTS), X-Content-Type-Options, X-XSS-Protection, and X-Frame-Options.
2. SSL/TLS configuration evaluation, including protocol version and cipher suite.
3. Examination of SSL/TLS certificate information, such as subject, issuer, and validity period.
4. Vulnerability scanning for SQL injection and Cross-Site Scripting (XSS) vulnerabilities.
5. Nmap scanning for network discovery and security auditing.

   
 <img width="599" alt="Screenshot 2024-03-05 at 9 21 15 PM" src="https://github.com/shreya241103/Web-Security-Scanner-SSL-TLS-Analyser/assets/115857097/652402c6-1764-4f2c-bc9f-9f2630762262">

 
ALL THESE HEADERS ARE SENT IN RESPONSE FROM THE SERVER:
Strict Transport Security (HSTS) header :
the absence of the Strict Transport Security (HSTS) header means that the website is not instructing the user's web browser to always use a secure HTTPS connection when communicating with the website
X-Content-Type-Options header.
The absence of the X-Content-Type-Options header means that the website is not instructing the user's web browser to prevent it from guessing the content type of a file based on its extension. This can leave the user's web browser vulnerable to attacks where an attacker can trick the browser into executing a malicious script or loading an untrusted resource.
X-XSS-Protection header. 
instructs the user's web browser to enable its built-in Cross-Site Scripting (XSS) filter. Cross-Site Scripting is a type of attack where an attacker injects malicious code into a web page, which can then execute on the user's web browser, potentially stealing sensitive information or performing unauthorised actions.
X-Frame-Options header .
it tells the user's web browser to either allow or deny the embedding of the web page within a frame or iframe. By denying the embedding of the web page, the X-Frame-Options header helps to prevent clickjacking attacks.
By including the X-Frame-Options header with the DENY value, the web server instructs the browser to deny the embedding of the web page in any iframe, preventing clickjacking attacks that rely on iframes to display malicious content on top of a legitimate website.



<img width="598" alt="Screenshot 2024-03-05 at 9 21 36 PM" src="https://github.com/shreya241103/Web-Security-Scanner-SSL-TLS-Analyser/assets/115857097/a95024d8-b4cc-44c4-a865-de72ff60e152">

  
HTTPS is a combination of HTTP with the SSL/TLS protocol,
Port 443 is commonly used for HTTPS 

Protocol Version: TLSv1.2
This is the version of the Transport Layer Security (TLS) protocol used for secure communication between the website server and the user's web browser. TLS is a cryptographic protocol that ensures secure transmission of data over the internet.
Cipher Suite: ECDHE-RSA-AES256-GCM-SHA384 
This is the cryptographic algorithm used to encrypt the data transmitted between the website server and the user's web browser. ECDHE-RSA-AES256-GCM-SHA384 is a strong and secure cipher suite that uses elliptic curve cryptography (ECDHE), RSA key exchange, AES-256 encryption, and Galois/Counter Mode (GCM) for authentication.
Together, these two parameters ensure that the SSL/TLS configuration for the website is secure and provides strong encryption for data transmitted between the website server and the user's web browser. This means that any sensitive information, such as login credentials or financial information, transmitted through the website is protected from eavesdropping and interception by third parties.



<img width="600" alt="Screenshot 2024-03-05 at 9 21 57 PM" src="https://github.com/shreya241103/Web-Security-Scanner-SSL-TLS-Analyser/assets/115857097/df7f6103-91c8-4e07-bc32-3f99101caef0">


SSL/TLS (Secure Sockets Layer/Transport Layer Security) certificates are digital certificates that establish a secure encrypted connection between a web server and a web browser. This ensures that any data exchanged between the server and browser is private and cannot be intercepted by any third party.
The output contains the following information:
1. Subject: This field contains the name of the entity that the certificate is issued to. In this case, the certificate is issued to a domain name "pes.edu" with the common name (CN) attribute.
2. Issuer: This field contains the name of the entity that issued the certificate. In this case, the certificate is issued by DigiCert, Inc., and GeoTrust Global TLS RSA4096 SHA256 2022 CA1 is the name of the certificate authority.
3. Serial Number: This field contains a unique identifier for the certificate.
4. Not Valid Before: This field indicates the date and time from which the certificate is valid. In this case, the certificate became valid from 2023-02-02 00:00:00.
5. Not Valid After: This field indicates the expiration date and time of the certificate. In this case, the certificate will expire on 2023-08-02 23:59:59. After this time, the certificate will no longer be valid and any secure connection attempts using this certificate will fail.

   
  
<img width="599" alt="Screenshot 2024-03-05 at 9 22 15 PM" src="https://github.com/shreya241103/Web-Security-Scanner-SSL-TLS-Analyser/assets/115857097/f9f9d4ff-f5ed-485a-a99f-1cb25bbee668">

SQL injection is a type of vulnerability where an attacker can inject malicious SQL code into a website's database, potentially allowing them to access or modify data they shouldn't have access to. XSS (Cross-site scripting) is a type of vulnerability that allows an attacker to inject malicious code into a website(in entry fields of website or in buttons,ALERT boxes), which can then be executed by other users who visit the site, potentially allowing the attacker to steal sensitive information or take control of the user's session.

The output is checks  for security vulnerabilities on a website.
1. The tool has found a vulnerability in the website's code called SQL Injection. This means that an attacker can potentially inject a malicious code (called SQL query) into the website's input fields (such as search boxes or login forms), which could result in unauthorised access to the website's database. In this case, the tool has tested this vulnerability by entering a specific input into the website's search box, which could be used for SQL injection attacks. The input is: https://pes.edu/' OR '1'='1. This input tries to test whether the website is vulnerable to SQL injection or not. Here, the tool is trying to select all the data in the database by checking whether '1' equals '1', which is always true. Therefore, if the website is vulnerable, it will return all the data stored in the database.
2. The tool has not found any vulnerabilities related to Cross-site scripting (XSS), which is another type of security vulnerability where an attacker can inject malicious code into a website to steal sensitive information or perform other harmful actions. This means that the website is properly securing against such attacks.


  
<img width="599" alt="Screenshot 2024-03-05 at 9 22 37 PM" src="https://github.com/shreya241103/Web-Security-Scanner-SSL-TLS-Analyser/assets/115857097/a8a4b842-962f-40d8-af9f-90583dba2f00">


The output is displaying the results of an Nmap scan, which is a network exploration and security auditing tool. The scan was performed on a website with the domain name "pes.edu", and it shows that the website has two open ports, which are port 80 for HTTP and port 443 for HTTPS.


Here is a breakdown of the output:


1. Starting Nmap 7.80: This line indicates that the Nmap tool version 7.80 was used for the scan.


2. Nmap scan report for pes.edu (52.172.204.196): This line shows the IP address of the target website that was scanned.


3. Host is up (0.031s latency): This line indicates that the target host (in this case, the website) is up and responsive, and it shows the latency of the response time.


4. Not shown: 998 filtered ports: This line indicates that Nmap has not shown the status of 998 ports as they have been filtered.


5. PORT STATE SERVICE: This line shows the list of ports that were scanned and their status.


6. 80/tcp open http: This line shows that port 80 for HTTP is open and accepting connections.


7. 443/tcp open https: This line shows that port 443 for HTTPS is open and accepting secure connections.


8. Nmap done: 1 IP address (1 host up) scanned in 8.27 seconds: This line indicates that the Nmap scan is completed, and it took 8.27 seconds to scan the target website.






VULNERABILITY CHECK:


  





The SQL injection payloads are a list of strings that could potentially exploit a SQL injection vulnerability in a web application. The script loops through each payload and appends it to the target URL before making an HTTP request with the requests library. If the response contains the string "error", it indicates that the payload was successful in exploiting the SQL injection vulnerability, and the script prints a message to indicate the vulnerability was found.


Similarly, the XSS payloads are a list of strings that could potentially exploit an XSS vulnerability in a web application. The script loops through each payload and appends it to the target URL before making an HTTP request. If the response contains the original payload string, it indicates that the payload was successful in exploiting the XSS vulnerability, and the script prints a message to indicate the vulnerability was found.If the target website is vulnerable to XSS and the payload is successfully executed, the content of the response will include the original payload string "alert("XSS")".


* The first payload ' OR '1'='1 is a common example of a SQL injection attack. In SQL, the OR operator returns true if either of its operands is true. By injecting ' OR '1'='1 into a SQL query, the attacker is effectively making the query always return true, as '1'='1' is always true. This could allow the attacker to bypass authentication checks or gain access to sensitive data.
* The second payload '; DROP TABLE users; is another example of a SQL injection attack. In this case, the attacker is injecting a SQL command that drops the entire "users" table from the database. This can cause permanent and irreversible data loss.
* The third payload SELECT * FROM users WHERE username = 'admin' AND password = 'password' is not actually an example of a SQL injection attack. Instead, it is a query that an attacker might use to attempt to log in as the administrator of a web application. If the application does not properly validate user input, the attacker could potentially bypass authentication by injecting this query into the login form.
The second list xss_payloads contains two examples of payloads used for cross-site scripting (XSS) attacks. XSS is a type of security vulnerability that allows an attacker to inject malicious scripts into a web page viewed by other users.
* The first payload <script>alert("XSS")</script> injects a script that displays an alert box with the message "XSS". If this script is injected into a web page and executed by another user's browser, it could potentially be used to steal sensitive information or perform other malicious actions.
* The second payload <img src="x" onerror="alert(\'XSS\')"> injects an image tag with a non-existent image source that triggers an onerror event when the browser tries to load the image. This event is used to execute a script that displays an alert box with the message "XSS". If this script is injected into a web page and executed by another user's browser, it could potentially be used to steal sensitive information or perform other malicious actions.
