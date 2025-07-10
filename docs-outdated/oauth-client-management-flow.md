# OAuth Client Management Flow

This document describes the comprehensive OAuth 2.1 client and scope management workflows using the `authly-admin` CLI interface.

## Overview

The CLI admin interface provides enterprise-grade tools for managing OAuth 2.1 clients and scopes with features including:

- **Complete CRUD Operations**: Create, read, update, delete for clients and scopes
- **Secure Credential Management**: Client secret generation and regeneration
- **Scope Association**: Client-scope relationship management
- **System Administration**: Status monitoring and configuration validation
- **Production Features**: JSON output, dry-run mode, verbose logging

## Visual Management Flow

![OAuth Client Management Flow](oauth-client-management-flow.mmd)

## Core Management Operations

### 1. Client Creation

Creates new OAuth 2.1 clients with comprehensive validation:

**Command:**
```bash
authly-admin client create \
  --name "My Application" \
  --type confidential \
  --redirect-uri "https://myapp.com/callback" \
  --scope "read write"
```

**Process Flow:**
1. **Input Validation**: Validates client type, redirect URIs, and scope names
2. **ID Generation**: Creates unique client_id (UUID format)
3. **Secret Generation**: Generates and hashes client_secret (confidential clients only)
4. **Database Storage**: Stores client data with proper constraints
5. **Scope Association**: Links client to requested scopes
6. **Response**: Returns client details including one-time secret display

**Security Features:**
- **bcrypt Secret Hashing**: Client secrets stored securely
- **PKCE Enforcement**: Automatic PKCE requirement for OAuth 2.1 compliance
- **URI Validation**: Redirect URI format and security validation
- **Scope Validation**: Ensures requested scopes exist and are active

### 2. Client Listing and Discovery

Retrieves client information with flexible filtering:

**Commands:**
```bash
# List active clients
authly-admin client list

# Paginated listing with JSON output
authly-admin client list --limit 10 --offset 20 --output json

# Include inactive clients
authly-admin client list --show-inactive
```

**Features:**
- **Pagination Support**: Efficient handling of large client datasets
- **Scope Information**: Shows associated scopes for each client
- **Multiple Formats**: Table view for humans, JSON for automation
- **Status Filtering**: Active/inactive client filtering

### 3. Client Details and Inspection

Detailed client information retrieval:

**Command:**
```bash
authly-admin client show "client-id-uuid" --output table
```

**Information Displayed:**
- **Basic Details**: Name, type, creation date, status
- **Authentication**: Auth method, PKCE requirements
- **URIs**: Redirect URIs, client URI, logo URI
- **Scopes**: Associated scope permissions
- **Security**: Last secret regeneration, activation status

### 4. Client Updates and Management

Modify existing client configurations:

**Commands:**
```bash
# Update client properties
authly-admin client update "client-id" \
  --name "Updated Name" \
  --client-uri "https://newdomain.com"

# Activate/deactivate clients
authly-admin client update "client-id" --activate
authly-admin client update "client-id" --deactivate
```

**Updatable Fields:**
- **Identity**: Client name, description, URIs
- **Configuration**: Redirect URIs, authentication methods
- **Status**: Activation/deactivation (soft delete)
- **Scope Associations**: Add/remove scope permissions

### 5. Secret Management

Secure client secret operations:

**Command:**
```bash
authly-admin client regenerate-secret "client-id" --confirm
```

**Process:**
1. **Client Validation**: Confirms client exists and is confidential
2. **Secret Generation**: Creates cryptographically secure new secret
3. **Secure Storage**: Hashes and stores new secret with bcrypt
4. **One-time Display**: Shows plaintext secret once for administrator
5. **Audit Trail**: Logs secret regeneration for security monitoring

**Security Considerations:**
- **Public Client Protection**: Prevents secret generation for public clients
- **Secure Display**: Plaintext secret shown only once during regeneration
- **Hash Storage**: Only bcrypt hashes stored in database
- **Audit Logging**: Secret operations logged for security compliance

### 6. Scope Management Integration

Comprehensive scope lifecycle management:

**Scope Creation:**
```bash
authly-admin scope create \
  --name "admin" \
  --description "Administrative access" \
  --default
```

**Scope Operations:**
- **Creation**: Define new permission scopes
- **Listing**: View all available scopes with descriptions
- **Updates**: Modify scope descriptions and default status
- **Default Management**: Configure automatically granted scopes
- **Association**: Link scopes to specific clients

### 7. System Administration

Monitoring and configuration management:

**Status Command:**
```bash
authly-admin status --verbose
```

**System Information:**
- **Database Connectivity**: Connection status and performance
- **Configuration**: Current settings and environment variables
- **Statistics**: Client and scope counts, usage metrics
- **Health Checks**: System component status validation

## Advanced CLI Features

### JSON Output for Automation

All commands support JSON output for scripting:

```bash
# Export all clients
authly-admin client list --output json > clients.json

# Pipe to jq for processing
authly-admin client list --output json | jq '.[] | .client_name'

# Automated client creation
CLIENT_ID=$(authly-admin client create --name "API Client" --type public \
  --redirect-uri "https://api.example.com/callback" --output json | \
  jq -r '.client_id')
```

### Dry-Run Mode

Preview operations without execution:

```bash
# Preview client creation
authly-admin --dry-run client create \
  --name "Test Client" \
  --type confidential \
  --redirect-uri "https://test.com/callback"

# Preview updates
authly-admin --dry-run client update "client-id" \
  --name "New Name"
```

### Configuration Management

Flexible configuration options:

```bash
# Use custom config file
authly-admin --config /path/to/config.toml client list

# Verbose output for debugging
authly-admin --verbose status

# Environment variable configuration
export DATABASE_URL="postgresql://..."
export JWT_SECRET_KEY="..."
authly-admin status
```

## Error Handling and Recovery

### Common Error Scenarios

1. **Database Connection Issues**
   - Clear error messages with connection troubleshooting
   - Automatic retry logic with exponential backoff
   - Configuration validation and suggestions

2. **Client Not Found**
   - Helpful error messages with client ID validation
   - Suggestions for finding correct client IDs
   - List command integration for discovery

3. **Validation Errors**
   - Detailed field-specific error messages
   - Examples of correct input formats
   - Reference to documentation and help

4. **Constraint Violations**
   - User-friendly explanations of database constraints
   - Suggestions for resolving conflicts
   - Automatic cleanup recommendations

### Recovery Operations

```bash
# Check system health
authly-admin status

# Validate database schema
authly-admin --verbose status

# List all clients to verify state
authly-admin client list --show-inactive

# Recreate missing clients
authly-admin client create --name "Backup Client" --type confidential \
  --redirect-uri "https://backup.example.com/callback"
```

## Security and Compliance

### Access Control
- **Admin Authentication**: CLI requires appropriate database permissions
- **Credential Protection**: No secrets exposed in logs or command history
- **Audit Logging**: All administrative operations logged

### Data Protection
- **Encryption**: Client secrets encrypted with bcrypt
- **Secure Transport**: Database connections use SSL/TLS
- **Memory Safety**: Sensitive data cleared from memory after use

### Compliance Features
- **OAuth 2.1 Standards**: Full RFC compliance in client management
- **GDPR Support**: Client data lifecycle management
- **SOC 2**: Audit trail and access control features

## Integration Patterns

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Deploy OAuth Clients
  run: |
    authly-admin client create \
      --name "Production App" \
      --type confidential \
      --redirect-uri "${{ secrets.PROD_REDIRECT_URI }}" \
      --output json > client.json
    
    CLIENT_ID=$(jq -r '.client_id' client.json)
    echo "::set-output name=client_id::$CLIENT_ID"
```

### Monitoring Integration

```bash
# Export metrics for monitoring
authly-admin status --output json | \
  jq '{clients: .statistics.active_clients, scopes: .statistics.active_scopes}'

# Health check for monitoring systems
authly-admin status && echo "OAuth system healthy"
```

### Backup and Restore

```bash
# Export all configuration
authly-admin client list --output json > clients_backup.json
authly-admin scope list --output json > scopes_backup.json

# Restore from backup (manual process)
while read client; do
  authly-admin client create \
    --name "$(echo $client | jq -r '.client_name')" \
    --type "$(echo $client | jq -r '.client_type')" \
    # ... additional parameters
done < clients_backup.json
```

This CLI management system provides enterprise-grade tools for OAuth 2.1 administration with comprehensive features for security, monitoring, and automation integration.