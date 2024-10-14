import os
import subprocess

def generate_ssl_certificate(domain='localhost', key_file='server.key', cert_file='server.crt', days_valid=365):
    # Generate a private key
    subprocess.run(['openssl', 'genrsa', '-out', key_file, '2048'], check=True)
    
    # Generate a Certificate Signing Request (CSR)
    csr_file = 'server.csr'
    subprocess.run(['openssl', 'req', '-new', '-key', key_file, '-out', csr_file, '-subj', f'/CN={domain}'], check=True)
    
    # Generate a self-signed SSL certificate
    subprocess.run(['openssl', 'x509', '-req', '-days', str(days_valid), '-in', csr_file, '-signkey', key_file, '-out', cert_file], check=True)
    
    # Clean up CSR file
    os.remove(csr_file)
    
    # Output the generated certificate details
    print(f"Generated SSL Certificate:\nPrivate Key: {key_file}\nCertificate: {cert_file}")

if __name__ == "__main__":
    domain = input("Enter the domain name for the SSL certificate (default: localhost): ") or 'localhost'
    generate_ssl_certificate(domain=domain)