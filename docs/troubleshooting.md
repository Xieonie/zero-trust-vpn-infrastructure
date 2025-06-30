# Troubleshooting Guide

This guide covers common issues and solutions for the Zero Trust VPN infrastructure.

## Table of Contents

1. [General Troubleshooting](#general-troubleshooting)
2. [WireGuard Issues](#wireguard-issues)
3. [Authentication Problems](#authentication-problems)
4. [Certificate Issues](#certificate-issues)
5. [Network Connectivity](#network-connectivity)
6. [Performance Problems](#performance-problems)
7. [Policy Issues](#policy-issues)
8. [Monitoring and Logging](#monitoring-and-logging)

## General Troubleshooting

### Basic Diagnostic Steps

1. **Check Service Status**
   ```bash
   # Check WireGuard status
   sudo systemctl status wg-quick@wg0
   
   # Check Authelia status
   sudo systemctl status authelia
   
   # Check Docker containers
   docker ps -a
   docker-compose ps
   ```

2. **Check Network Connectivity**
   ```bash
   # Test internet connectivity
   ping 8.8.8.8
   
   # Test DNS resolution
   nslookup google.com
   
   # Check listening ports
   netstat -tlnp | grep -E "(51820|9091)"
   ```

3. **Check Logs**
   ```bash
   # WireGuard logs
   sudo journalctl -u wg-quick@wg0 -f
   
   # Authelia logs
   sudo journalctl -u authelia -f
   
   # Docker logs
   docker logs wireguard
   docker logs authelia
   ```

## WireGuard Issues

### Connection Problems

#### Client Cannot Connect

**Symptoms:**
- Connection timeout
- Handshake failures
- No response from server

**Diagnosis:**
```bash
# Check WireGuard interface
sudo wg show

# Check if interface is up
ip addr show wg0

# Check firewall rules
sudo iptables -L -n | grep 51820

# Test UDP connectivity
nc -u server_ip 51820
```

**Solutions:**

1. **Firewall Issues**
   ```bash
   # Allow WireGuard port
   sudo ufw allow 51820/udp
   
   # Check iptables rules
   sudo iptables -I INPUT -p udp --dport 51820 -j ACCEPT
   ```

2. **Configuration Issues**
   ```bash
   # Verify server configuration
   sudo cat /etc/wireguard/wg0.conf
   
   # Check for syntax errors
   sudo wg-quick down wg0
   sudo wg-quick up wg0
   ```

3. **Key Mismatch**
   ```bash
   # Regenerate keys if needed
   wg genkey | tee private.key | wg pubkey > public.key
   
   # Update configuration with new keys
   sudo nano /etc/wireguard/wg0.conf
   ```

#### Handshake Failures

**Symptoms:**
- "Handshake did not complete" errors
- Connection established but no data transfer

**Diagnosis:**
```bash
# Check handshake status
sudo wg show wg0 latest-handshakes

# Monitor handshake attempts
sudo wg show wg0 dump
```

**Solutions:**

1. **Time Synchronization**
   ```bash
   # Check system time
   timedatectl status
   
   # Sync time if needed
   sudo ntpdate -s time.nist.gov
   ```

2. **MTU Issues**
   ```bash
   # Test different MTU sizes
   ping -M do -s 1472 destination_ip
   
   # Adjust MTU in WireGuard config
   MTU = 1420
   ```

3. **NAT/Firewall Issues**
   ```bash
   # Enable IP forwarding
   echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
   
   # Add NAT rules
   sudo iptables -t nat -A POSTROUTING -s 10.100.0.0/24 -o eth0 -j MASQUERADE
   ```

### Performance Issues

#### Slow Connection Speeds

**Diagnosis:**
```bash
# Test bandwidth
speedtest-cli

# Check CPU usage
top -p $(pgrep wg)

# Monitor network interface
iftop -i wg0
```

**Solutions:**

1. **Optimize Configuration**
   ```ini
   # In wg0.conf
   MTU = 1420
   PersistentKeepalive = 25
   ```

2. **Server Optimization**
   ```bash
   # Increase network buffers
   echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
   echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
   sudo sysctl -p
   ```

## Authentication Problems

### Authelia Login Issues

#### Cannot Access Login Page

**Symptoms:**
- 502 Bad Gateway
- Connection refused
- Timeout errors

**Diagnosis:**
```bash
# Check Authelia service
sudo systemctl status authelia

# Check configuration
authelia validate-config /etc/authelia/configuration.yml

# Test local connectivity
curl -I http://localhost:9091
```

**Solutions:**

1. **Service Issues**
   ```bash
   # Restart Authelia
   sudo systemctl restart authelia
   
   # Check for configuration errors
   sudo journalctl -u authelia --no-pager
   ```

2. **Database Connection**
   ```bash
   # Test database connectivity
   psql -h localhost -U authelia -d authelia
   
   # Check database logs
   sudo journalctl -u postgresql
   ```

#### Authentication Failures

**Symptoms:**
- "Invalid credentials" errors
- Users cannot log in with correct passwords
- 2FA failures

**Diagnosis:**
```bash
# Check user database
cat /etc/authelia/users_database.yml

# Verify password hash
docker run --rm authelia/authelia:latest authelia hash-password 'password'

# Check authentication logs
grep "authentication failed" /var/log/authelia/authelia.log
```

**Solutions:**

1. **Password Issues**
   ```bash
   # Generate new password hash
   docker run --rm authelia/authelia:latest authelia hash-password 'newpassword'
   
   # Update users database
   sudo nano /etc/authelia/users_database.yml
   ```

2. **2FA Issues**
   ```bash
   # Check time synchronization
   timedatectl status
   
   # Reset user 2FA (remove from database)
   # User will need to re-register 2FA device
   ```

### LDAP Integration Issues

#### LDAP Connection Failures

**Diagnosis:**
```bash
# Test LDAP connectivity
ldapsearch -x -H ldap://ldap.server.com -D "cn=user,dc=domain,dc=com" -W

# Check LDAP configuration in Authelia
grep -A 20 "ldap:" /etc/authelia/configuration.yml
```

**Solutions:**

1. **Connection Issues**
   ```bash
   # Test network connectivity
   telnet ldap.server.com 389
   
   # Check firewall rules
   sudo ufw allow from authelia_server_ip to ldap_server_ip port 389
   ```

2. **Authentication Issues**
   ```bash
   # Verify service account credentials
   ldapwhoami -x -D "cn=authelia,ou=service,dc=domain,dc=com" -W
   
   # Check user search filter
   ldapsearch -x -D "cn=authelia,ou=service,dc=domain,dc=com" -W \
     -b "ou=users,dc=domain,dc=com" "(uid=username)"
   ```

## Certificate Issues

### Certificate Validation Errors

#### Expired Certificates

**Symptoms:**
- "Certificate has expired" errors
- SSL/TLS handshake failures
- Browser security warnings

**Diagnosis:**
```bash
# Check certificate expiration
openssl x509 -in /path/to/cert.pem -noout -dates

# Check certificate chain
openssl s_client -connect vpn.domain.com:443 -showcerts
```

**Solutions:**

1. **Renew Certificates**
   ```bash
   # Using cert-renewal script
   ./scripts/automation/cert-renewal.sh renew
   
   # Manual renewal
   ./scripts/automation/cert-renewal.sh generate-server
   ```

2. **Update Certificate References**
   ```bash
   # Update WireGuard configuration
   sudo nano /etc/wireguard/wg0.conf
   
   # Update Authelia configuration
   sudo nano /etc/authelia/configuration.yml
   
   # Restart services
   sudo systemctl restart wg-quick@wg0 authelia
   ```

#### Certificate Chain Issues

**Diagnosis:**
```bash
# Verify certificate chain
openssl verify -CAfile ca.pem server.pem

# Check certificate details
openssl x509 -in server.pem -text -noout
```

**Solutions:**

1. **Fix Certificate Chain**
   ```bash
   # Concatenate certificates in correct order
   cat server.pem intermediate.pem ca.pem > fullchain.pem
   
   # Update configuration to use full chain
   ```

### PKI Management Issues

#### CA Certificate Problems

**Diagnosis:**
```bash
# Check CA certificate
openssl x509 -in ca.pem -text -noout

# Verify CA can sign certificates
openssl verify -CAfile ca.pem server.pem
```

**Solutions:**

1. **Regenerate CA (Last Resort)**
   ```bash
   # Backup existing certificates
   cp -r /etc/zero-trust-vpn/pki /backup/pki-$(date +%Y%m%d)
   
   # Generate new CA
   ./scripts/automation/cert-renewal.sh generate-ca --force
   
   # Regenerate all certificates
   ./scripts/automation/cert-renewal.sh generate-server
   ```

## Network Connectivity

### Routing Issues

#### Cannot Reach Internal Networks

**Symptoms:**
- VPN connects but cannot access internal resources
- Partial connectivity to some networks
- DNS resolution failures

**Diagnosis:**
```bash
# Check routing table
ip route show

# Test connectivity to internal networks
ping 192.168.1.1

# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward
```

**Solutions:**

1. **Enable IP Forwarding**
   ```bash
   # Temporary
   echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
   
   # Permanent
   echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
   sudo sysctl -p
   ```

2. **Fix Routing**
   ```bash
   # Add routes for internal networks
   ip route add 192.168.1.0/24 via 10.100.0.1
   
   # Update WireGuard configuration
   PostUp = ip route add 192.168.1.0/24 via 10.100.0.1
   ```

3. **NAT Configuration**
   ```bash
   # Add NAT rules
   iptables -t nat -A POSTROUTING -s 10.100.0.0/24 -d 192.168.1.0/24 -j MASQUERADE
   
   # Save rules
   iptables-save > /etc/iptables/rules.v4
   ```

### DNS Issues

#### DNS Resolution Failures

**Diagnosis:**
```bash
# Test DNS resolution
nslookup google.com
dig @8.8.8.8 google.com

# Check DNS configuration
cat /etc/resolv.conf

# Test internal DNS
nslookup internal.domain.com
```

**Solutions:**

1. **Fix DNS Configuration**
   ```bash
   # Update WireGuard client configuration
   DNS = 10.100.0.1, 8.8.8.8
   
   # Configure DNS server on VPN server
   # Install and configure dnsmasq or bind9
   ```

2. **DNS Forwarding**
   ```bash
   # Configure conditional forwarding
   # Forward internal domains to internal DNS
   # Forward external domains to public DNS
   ```

## Performance Problems

### High Latency

#### Network Latency Issues

**Diagnosis:**
```bash
# Test latency
ping -c 10 destination

# Trace route
traceroute destination

# Monitor network performance
mtr destination
```

**Solutions:**

1. **Optimize Network Path**
   ```bash
   # Choose closer VPN server
   # Optimize routing
   # Check for network congestion
   ```

2. **Tune Network Parameters**
   ```bash
   # Increase network buffers
   echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
   echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
   
   # Optimize TCP settings
   echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
   ```

### High CPU Usage

#### Server Performance Issues

**Diagnosis:**
```bash
# Monitor CPU usage
top -p $(pgrep wg)
htop

# Check system load
uptime

# Monitor system resources
iostat 1
```

**Solutions:**

1. **Optimize WireGuard**
   ```bash
   # Use hardware acceleration if available
   # Reduce connection count
   # Optimize configuration
   ```

2. **Scale Infrastructure**
   ```bash
   # Add more VPN servers
   # Load balance connections
   # Upgrade server hardware
   ```

## Policy Issues

### Access Control Problems

#### Users Cannot Access Resources

**Diagnosis:**
```bash
# Check access control policies
cat /etc/authelia/access-control.yml

# Test policy evaluation
# Check user groups and permissions
```

**Solutions:**

1. **Review Policies**
   ```yaml
   # Update access control rules
   access_control:
     default_policy: deny
     rules:
       - domain: "internal.domain.com"
         policy: two_factor
         subject: "group:users"
   ```

2. **Test Policy Changes**
   ```bash
   # Validate configuration
   authelia validate-config /etc/authelia/configuration.yml
   
   # Restart Authelia
   sudo systemctl restart authelia
   ```

## Monitoring and Logging

### Log Analysis

#### Finding Issues in Logs

**Common Log Locations:**
```bash
# WireGuard logs
/var/log/wireguard/
journalctl -u wg-quick@wg0

# Authelia logs
/var/log/authelia/
journalctl -u authelia

# System logs
/var/log/syslog
/var/log/auth.log
```

**Useful Log Searches:**
```bash
# Authentication failures
grep "authentication failed" /var/log/authelia/authelia.log

# Connection attempts
grep "handshake" /var/log/wireguard/wg0.log

# Policy violations
grep "access denied" /var/log/authelia/authelia.log

# Certificate errors
grep -i "certificate" /var/log/authelia/authelia.log
```

### Health Monitoring

#### Service Health Checks

**Automated Monitoring:**
```bash
# Create health check script
#!/bin/bash
# Check WireGuard
if ! systemctl is-active --quiet wg-quick@wg0; then
    echo "WireGuard is down"
    # Send alert
fi

# Check Authelia
if ! curl -f http://localhost:9091/api/health; then
    echo "Authelia is unhealthy"
    # Send alert
fi
```

## Emergency Procedures

### Service Recovery

#### Complete System Recovery

**Steps:**
1. **Stop all services**
   ```bash
   sudo systemctl stop wg-quick@wg0
   sudo systemctl stop authelia
   docker-compose down
   ```

2. **Check system resources**
   ```bash
   df -h
   free -h
   ps aux | head -20
   ```

3. **Restore from backup**
   ```bash
   # Restore configuration
   cp /backup/config/* /etc/zero-trust-vpn/
   
   # Restore certificates
   cp /backup/pki/* /etc/zero-trust-vpn/pki/
   ```

4. **Start services**
   ```bash
   sudo systemctl start authelia
   sudo systemctl start wg-quick@wg0
   docker-compose up -d
   ```

### Emergency Access

#### Bypass Authentication (Emergency Only)

**Temporary bypass for emergency access:**
```bash
# Create emergency access rule
# ONLY use in true emergencies
# Remove immediately after emergency

# Add to Authelia configuration temporarily
access_control:
  rules:
    - domain: "emergency.domain.com"
      policy: bypass
      networks:
        - "trusted_admin_ip/32"
```

## Getting Help

### Community Resources
- **WireGuard**: https://lists.zx2c4.com/mailman/listinfo/wireguard
- **Authelia**: https://github.com/authelia/authelia/discussions
- **Zero Trust**: https://www.nist.gov/publications/zero-trust-architecture

### Professional Support
- Consider professional support for production environments
- Regular security audits and penetration testing
- Incident response planning
- Disaster recovery testing

### Documentation
- Keep detailed documentation of all changes
- Document troubleshooting procedures
- Maintain network diagrams
- Record all emergency procedures