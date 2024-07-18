# Web Security Scanner

The Web Security Scanner project is designed to provide in-depth insights into the security vulnerabilities and configurations of web applications. This tool performs various checks to help identify potential security issues and ensure robust protection for web applications.

## Features

1. **Security Header Analysis:**
   - Checks for the presence and proper configuration of important security headers, including:
     - **Strict Transport Security (HSTS)**
     - **X-Content-Type-Options**
     - **X-XSS-Protection**
     - **X-Frame-Options**

2. **SSL/TLS Configuration Evaluation:**
   - Evaluates SSL/TLS settings, including:
     - **Protocol Version:** Ensures the use of secure TLS versions.
     - **Cipher Suite:** Checks for strong and secure cryptographic algorithms.

3. **SSL/TLS Certificate Examination:**
   - Analyzes certificate details such as:
     - **Subject**
     - **Issuer**
     - **Validity Period**

4. **Vulnerability Scanning:**
   - Detects vulnerabilities such as:
     - **SQL Injection**
     - **Cross-Site Scripting (XSS)**

5. **Network Discovery:**
   - Uses Nmap to perform network discovery and security auditing.

## Screenshots

### Security Headers

![Security Headers](https://github.com/shreya241103/Web-Security-Scanner-SSL-TLS-Analyser/assets/115857097/652402c6-1764-4f2c-bc9f-9f2630762262)

- **Strict Transport Security (HSTS):** Ensures secure HTTPS connections.
- **X-Content-Type-Options:** Prevents browsers from guessing content types, reducing vulnerability to attacks.
- **X-XSS-Protection:** Enables the browser's built-in XSS filter to mitigate Cross-Site Scripting attacks.
- **X-Frame-Options:** Prevents clickjacking by controlling frame embedding.

### SSL/TLS Configuration

![SSL/TLS Configuration](https://github.com/shreya241103/Web-Security-Scanner-SSL-TLS-Analyser/assets/115857097/a95024d8-b4cc-44c4-a865-de72ff60e152)

- **Protocol Version:** TLSv1.2 ensures secure communication.
- **Cipher Suite:** ECDHE-RSA-AES256-GCM-SHA384 provides strong encryption.

### SSL/TLS Certificate Details

![SSL/TLS Certificate](https://github.com/shreya241103/Web-Security-Scanner-SSL-TLS-Analyser/assets/115857097/df7f6103-91c8-4e07-bc32-3f99101caef0)

- **Subject:** Domain name and attributes.
- **Issuer:** Certificate authority.
- **Validity Period:** Certificate validity dates.

### Vulnerability Scanning

![Vulnerability Scanning](https://github.com/shreya241103/Web-Security-Scanner-SSL-TLS-Analyser/assets/115857097/f9f9d4ff-f5ed-485a-a99f-1cb25bbee668)

- **SQL Injection:** Checks for vulnerabilities allowing unauthorized database access.
- **Cross-Site Scripting (XSS):** Identifies potential for malicious script injection.

### Network Discovery

![Network Discovery](https://github.com/shreya241103/Web-Security-Scanner-SSL-TLS-Analyser/assets/115857097/a8a4b842-962f-40d8-af9f-90583dba2f00)

- **Port Scanning:** Identifies open ports, including 80 (HTTP) and 443 (HTTPS).

## Usage

## Clone the Repository
1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/web-scanning-app.git
    ```
2. Navigate to the project directory:
    ```sh
    cd web-scanning-app
    ```

## Running the Server
1. Open a terminal and navigate to the project directory.
2. Run the server script:
    ```sh
    python server.py
    ```

## Running the Client
1. Open a terminal and navigate to the project directory.
2. Run the client script:
    ```sh
    python client.py
    ```
3. Enter the URL when prompted. The client will send the URL to the server and display the server's response.

