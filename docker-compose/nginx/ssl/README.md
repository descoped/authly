# SSL Certificates for Nginx

This directory contains SSL certificates for the Nginx reverse proxy.

## Certificate Files

Place your SSL certificates in this directory:
- `cert.pem` - SSL certificate file  
- `key.pem` - SSL private key file

**⚠️ SECURITY: Never commit certificates to version control!**

## Development Setup

Create self-signed certificates for local development:

```bash
# Run from project root
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout docker-compose/nginx/ssl/key.pem \
  -out docker-compose/nginx/ssl/cert.pem \
  -subj "/C=US/ST=Development/L=Localhost/O=Authly/CN=localhost"
```

## Production Setup

### Option 1: Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt-get install certbot

# Generate certificates (replace with your domain)
sudo certbot certonly --standalone -d auth.yourdomain.com

# Copy certificates to docker directory
sudo cp /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem docker-compose/nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem docker-compose/nginx/ssl/key.pem
sudo chown $(whoami):$(whoami) docker-compose/nginx/ssl/*.pem
```

### Option 2: Custom CA Certificate

Place your certificate authority issued certificates:
- Copy your certificate chain to `cert.pem`
- Copy your private key to `key.pem`

## Certificate Renewal

For Let's Encrypt certificates, set up automatic renewal:

```bash
# Add to crontab (crontab -e)
0 12 * * * /usr/bin/certbot renew --quiet && docker compose restart nginx
```