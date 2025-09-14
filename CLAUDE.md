# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This repository contains bash scripts for setting up and managing secure NGINX reverse proxies with automated SSL certificate management using Let's Encrypt and acme.sh.

## Architecture

The system consists of two main components:

1. **domain-proxy-init.sh** - Initial system hardening and NGINX setup script that:
   - Hardens Ubuntu 24.04 with security packages (ufw, fail2ban)
   - Installs and configures NGINX with security headers and rate limiting
   - Sets up acme.sh for automated SSL certificate management
   - Creates directory structure and common configuration files

2. **domain-proxy-manager.sh** - Domain management script that:
   - Adds new domains with SSL-enabled reverse proxy configurations
   - Manages path-based redirects within domains
   - Provides configuration rollback capabilities
   - Validates DNS resolution before certificate requests
   - Handles both webroot and DNS challenges for SSL certificates

## Key Directory Structure

- `/etc/nginx/conf.d/domains/` - Domain-specific NGINX configurations
- `/etc/nginx/conf.d/common/` - Shared configuration files (security headers, error pages)
- `/etc/ssl/clients/` - SSL certificate storage
- `/etc/nginx/backups/` - Configuration backups for rollback
- `/var/www/error_pages/` - Custom error page templates

## Common Commands

### Initial Setup
```bash
sudo ./domain-proxy-init.sh
```

### Domain Management
```bash
# Add a new domain with reverse proxy
sudo ./domain-proxy-manager.sh add example.com http://localhost:3000

# Add path redirect within existing domain
sudo ./domain-proxy-manager.sh redirect example.com /api https://api.example.com

# List all configured domains
./domain-proxy-manager.sh list

# Rollback domain to previous configuration
sudo ./domain-proxy-manager.sh rollback example.com

# Reload NGINX configuration
sudo ./domain-proxy-manager.sh reload
```

### System Validation
```bash
# Test NGINX configuration
sudo nginx -t

# Check certificate status
/root/.acme.sh/acme.sh --list

# View domain logs
sudo tail -f /var/log/nginx/example.com.access.log
```

## Security Features

- Rate limiting (10 requests/second with burst of 20)
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Automatic HTTP to HTTPS redirects
- SSL certificate auto-renewal via cron
- Fail2ban integration for brute force protection
- UFW firewall with minimal open ports

## Certificate Management

The system uses acme.sh with Let's Encrypt and supports:
- Webroot challenge (preferred method)
- DNS challenge fallback (requires CF_Key and CF_Email environment variables for Cloudflare)
- Automatic certificate renewal every 60 days
- Graceful NGINX reload on certificate updates

## Error Handling

- DNS resolution validation before certificate requests
- Configuration backup before any changes
- NGINX configuration validation before reload
- Rollback capability to previous working configurations
- Detailed logging for troubleshooting
