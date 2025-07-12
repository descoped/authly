# Authly CLI Administration Guide

Complete command-line interface guide for administering the Authly OAuth 2.1 + OpenID Connect 1.0 authorization server.

**CLI Access**: `python -m authly`  
**Admin Commands**: `python -m authly admin`  
**Architecture**: API-first (CLI uses HTTP API exclusively)

---

## 🚀 **Quick Start**

### **Installation & Setup**
```bash
# Install Authly (all groups including test/dev with forced update)
uv sync --all-groups -U

# Start Authly server (embedded development mode)
uv run python -m authly serve --embedded --dev

# In another terminal, access admin CLI
uv run python -m authly admin --help
```

### **First-Time Setup**
```bash
# Login to admin interface
uv run python -m authly admin login
# Enter admin credentials when prompted

# Create your first OAuth client
uv run python -m authly admin client create \
  --name "My Application" \
  --type confidential \
  --redirect-uri "https://myapp.com/callback"

# Create a scope
uv run python -m authly admin scope create \
  --name "read" \
  --description "Read access to user data"

# Check system status
uv run python -m authly admin status
```

---

## 📋 **CLI Structure**

### **Main Commands**
```bash
python -m authly [OPTIONS] COMMAND [ARGS]...

Commands:
  admin   Administrative operations for Authly
  serve   Start the Authly web service
```

### **Global Options**
```bash
--version    Show version and exit
--help       Show help message and exit
```

---

## 🌐 **Server Commands**

### **Start Authly Server**

#### **python -m authly serve**
Start the Authly web service in production mode.

**Options**:
```bash
--host TEXT        Host to bind (default: 0.0.0.0)
--port INTEGER     Port to bind (default: 8000)
--workers INTEGER  Number of worker processes
--reload           Enable auto-reload for development
--embedded         Start with embedded PostgreSQL container
--dev              Enable development mode with debug logging
```

**Examples**:
```bash
# Production server
python -m authly serve --host 0.0.0.0 --port 8000

# Development with embedded database
python -m authly serve --embedded --dev --reload

# Multi-worker production
python -m authly serve --workers 4
```

**Environment Variables**:
```bash
DATABASE_URL="postgresql://user:pass@host:5432/authly"
JWT_SECRET_KEY="your-secret-key"
JWT_REFRESH_SECRET_KEY="your-refresh-secret"
AUTHLY_ADMIN_API_ENABLED="true"
```

---

## 👑 **Admin Commands**

All admin commands use the format: `python -m authly admin COMMAND`

### **Authentication**

#### **python -m authly admin login**
Authenticate with the Authly admin API.

**Interactive Login**:
```bash
$ python -m authly admin login
Username: admin
Password: [hidden]
✓ Successfully logged in as admin
Token stored securely in ~/.authly/tokens.json
```

**Options**:
```bash
--username TEXT    Admin username
--password TEXT    Admin password (not recommended for security)
--api-url TEXT     Admin API URL (default: auto-detect)
```

**Examples**:
```bash
# Interactive login (recommended)
python -m authly admin login

# Non-interactive (CI/CD environments only)
python -m authly admin login --username admin --password "$ADMIN_PASSWORD"

# Custom API URL
python -m authly admin login --api-url "https://auth.mycompany.com"
```

#### **python -m authly admin logout**
Logout from the admin API and clear stored tokens.

```bash
$ python -m authly admin logout
✓ Successfully logged out
Tokens cleared from ~/.authly/tokens.json
```

#### **python -m authly admin whoami**
Show current authentication status.

```bash
$ python -m authly admin whoami
✓ Authenticated as: admin
✓ Token expires: 2025-07-10 15:30:00 UTC
✓ Scopes: admin:clients:read, admin:clients:write, admin:scopes:read, admin:scopes:write
```

---

### **OAuth Client Management**

#### **python -m authly admin client create**
Create a new OAuth 2.1 client.

**Required Options**:
```bash
--name TEXT             Client display name
--type [confidential|public]  Client type
--redirect-uri TEXT     Redirect URI (can be used multiple times)
```

**Optional Options**:
```bash
--scope TEXT           Assign scope to client (can be used multiple times)
--client-uri TEXT      Client homepage URL
--logo-uri TEXT        Client logo URL
--tos-uri TEXT         Terms of service URL
--policy-uri TEXT      Privacy policy URL
--contacts TEXT        Contact email (can be used multiple times)
```

**Examples**:
```bash
# Basic confidential client
python -m authly admin client create \
  --name "My Web App" \
  --type confidential \
  --redirect-uri "https://myapp.com/callback"

# Public client with multiple redirect URIs
python -m authly admin client create \
  --name "My Mobile App" \
  --type public \
  --redirect-uri "myapp://callback" \
  --redirect-uri "http://localhost:3000/callback"

# Client with metadata and scopes
python -m authly admin client create \
  --name "Enterprise App" \
  --type confidential \
  --redirect-uri "https://enterprise.com/oauth/callback" \
  --scope "read" \
  --scope "write" \
  --client-uri "https://enterprise.com" \
  --contacts "admin@enterprise.com"
```

**Success Output**:
```bash
✓ Client created successfully

Client ID: 7f9a8b2c-1234-5678-9abc-def012345678
Client Secret: cs_1a2b3c4d5e6f7g8h9i0j...
Name: My Web App
Type: confidential
Redirect URIs: https://myapp.com/callback
Scopes: read, write
Status: active

⚠️  Save the client secret securely - it cannot be retrieved again!
```

#### **python -m authly admin client list**
List OAuth clients.

**Options**:
```bash
--limit INTEGER        Number of clients to show (default: 20)
--offset INTEGER       Pagination offset (default: 0)
--show-inactive        Include inactive clients
--output [table|json]  Output format (default: table)
```

**Examples**:
```bash
# List active clients
python -m authly admin client list

# Show all clients including inactive
python -m authly admin client list --show-inactive

# JSON output for scripting
python -m authly admin client list --output json

# Paginated listing
python -m authly admin client list --limit 10 --offset 20
```

**Table Output**:
```bash
┌──────────────────────────────────────┬─────────────────┬──────────────┬────────┬─────────────────────┐
│ Client ID                            │ Name            │ Type         │ Status │ Created             │
├──────────────────────────────────────┼─────────────────┼──────────────┼────────┼─────────────────────┤
│ 7f9a8b2c-1234-5678-9abc-def012345678 │ My Web App      │ confidential │ active │ 2025-07-10 10:00:00 │
│ 8e8b7a1d-5678-9012-cdef-345678901234 │ My Mobile App   │ public       │ active │ 2025-07-10 11:00:00 │
└──────────────────────────────────────┴─────────────────┴──────────────┴────────┴─────────────────────┘

Total: 2 clients
```

#### **python -m authly admin client show CLIENT_ID**
Show detailed information about a specific client.

**Arguments**:
```bash
CLIENT_ID    UUID or client_id of the OAuth client
```

**Options**:
```bash
--output [table|json]  Output format (default: table)
--show-secret          Show client secret (confidential clients only)
```

**Examples**:
```bash
# Show client details
python -m authly admin client show 7f9a8b2c-1234-5678-9abc-def012345678

# Show with client secret
python -m authly admin client show my-web-app --show-secret

# JSON output
python -m authly admin client show my-web-app --output json
```

**Output**:
```bash
OAuth Client Details

Client ID: 7f9a8b2c-1234-5678-9abc-def012345678
Name: My Web App
Type: confidential
Status: active
Created: 2025-07-10 10:00:00 UTC
Updated: 2025-07-10 10:00:00 UTC

Redirect URIs:
  • https://myapp.com/callback

Assigned Scopes:
  • read - Read access to user data
  • write - Write access to user data

Client Metadata:
  • Client URI: https://myapp.com
  • Logo URI: https://myapp.com/logo.png
  • Contacts: admin@myapp.com
```

#### **python -m authly admin client update CLIENT_ID**
Update an existing OAuth client.

**Arguments**:
```bash
CLIENT_ID    UUID or client_id of the OAuth client
```

**Options**:
```bash
--name TEXT            Update client name
--add-redirect-uri TEXT    Add redirect URI
--remove-redirect-uri TEXT Remove redirect URI
--add-scope TEXT       Add scope to client
--remove-scope TEXT    Remove scope from client
--client-uri TEXT      Update client homepage URL
--logo-uri TEXT        Update client logo URL
--activate             Activate the client
--deactivate          Deactivate the client
```

**Examples**:
```bash
# Update client name
python -m authly admin client update my-web-app --name "Updated Web App"

# Add redirect URI
python -m authly admin client update my-web-app \
  --add-redirect-uri "https://myapp.com/oauth/callback"

# Add multiple scopes
python -m authly admin client update my-web-app \
  --add-scope "profile" \
  --add-scope "email"

# Deactivate client
python -m authly admin client update my-web-app --deactivate
```

#### **python -m authly admin client regenerate-secret CLIENT_ID**
Regenerate client secret for confidential clients.

**Arguments**:
```bash
CLIENT_ID    UUID or client_id of the OAuth client
```

**Options**:
```bash
--confirm    Skip confirmation prompt
```

**Examples**:
```bash
# Interactive regeneration
python -m authly admin client regenerate-secret my-web-app

# Skip confirmation
python -m authly admin client regenerate-secret my-web-app --confirm
```

**Output**:
```bash
⚠️  This will invalidate the current client secret!
   All applications using this client must be updated.

Continue? [y/N]: y

✓ Client secret regenerated successfully

New Client Secret: cs_9z8y7x6w5v4u3t2s1r0q...

⚠️  Save this secret securely - it cannot be retrieved again!
```

#### **python -m authly admin client delete CLIENT_ID**
Delete (deactivate) an OAuth client.

**Arguments**:
```bash
CLIENT_ID    UUID or client_id of the OAuth client
```

**Options**:
```bash
--confirm    Skip confirmation prompt
--permanent  Permanently delete instead of deactivating
```

**Examples**:
```bash
# Soft delete (deactivate)
python -m authly admin client delete my-web-app

# Permanent deletion
python -m authly admin client delete my-web-app --permanent --confirm
```

---

### **OAuth Scope Management**

#### **python -m authly admin scope create**
Create a new OAuth scope.

**Required Options**:
```bash
--name TEXT         Scope name (e.g., 'read', 'write', 'profile')
--description TEXT  Human-readable description
```

**Optional Options**:
```bash
--default          Make this a default scope (assigned automatically)
```

**Examples**:
```bash
# Basic scope
python -m authly admin scope create \
  --name "read" \
  --description "Read access to user data"

# Default scope
python -m authly admin scope create \
  --name "profile" \
  --description "Access to user profile information" \
  --default
```

#### **python -m authly admin scope list**
List OAuth scopes.

**Options**:
```bash
--show-inactive        Include inactive scopes
--output [table|json]  Output format (default: table)
```

**Examples**:
```bash
# List active scopes
python -m authly admin scope list

# Include inactive scopes
python -m authly admin scope list --show-inactive

# JSON output
python -m authly admin scope list --output json
```

**Output**:
```bash
┌─────────┬────────────────────────────────┬─────────┬────────┬─────────────────────┐
│ Name    │ Description                    │ Default │ Status │ Created             │
├─────────┼────────────────────────────────┼─────────┼────────┼─────────────────────┤
│ read    │ Read access to user data       │ No      │ active │ 2025-07-10 10:00:00 │
│ write   │ Write access to user data      │ No      │ active │ 2025-07-10 10:30:00 │
│ profile │ Access to user profile info    │ Yes     │ active │ 2025-07-10 11:00:00 │
└─────────┴────────────────────────────────┴─────────┴────────┴─────────────────────┘

Total: 3 scopes (2 active, 1 default)
```

#### **python -m authly admin scope show SCOPE_NAME**
Show detailed information about a specific scope.

**Arguments**:
```bash
SCOPE_NAME    Name of the OAuth scope
```

**Examples**:
```bash
# Show scope details
python -m authly admin scope show read
```

#### **python -m authly admin scope update SCOPE_NAME**
Update an existing OAuth scope.

**Arguments**:
```bash
SCOPE_NAME    Name of the OAuth scope
```

**Options**:
```bash
--description TEXT     Update description
--set-default         Make this a default scope
--unset-default       Remove default scope status
--activate            Activate the scope
--deactivate         Deactivate the scope
```

**Examples**:
```bash
# Update description
python -m authly admin scope update read \
  --description "Read access to user data and profile"

# Make default scope
python -m authly admin scope update profile --set-default

# Deactivate scope
python -m authly admin scope update old-scope --deactivate
```

#### **python -m authly admin scope delete SCOPE_NAME**
Delete (deactivate) an OAuth scope.

**Arguments**:
```bash
SCOPE_NAME    Name of the OAuth scope
```

**Options**:
```bash
--confirm     Skip confirmation prompt
--permanent   Permanently delete instead of deactivating
```

---

### **System Status & Information**

#### **python -m authly admin status**
Show system status and configuration.

**Options**:
```bash
--output [table|json]  Output format (default: table)
--verbose              Show detailed information
```

**Examples**:
```bash
# Basic status
python -m authly admin status

# Verbose status with details
python -m authly admin status --verbose

# JSON output for monitoring
python -m authly admin status --output json
```

**Output**:
```bash
Authly System Status

🟢 System Health: Healthy
📊 Version: 1.0.0
⏱️  Uptime: 2 days, 5 hours, 30 minutes

Database:
  Status: Connected
  Pool Size: 10
  Active Connections: 3

OAuth Metrics:
  Active Clients: 5
  Total Scopes: 8
  Active Tokens: 127

Admin API:
  Status: Enabled
  URL: http://localhost:8000
  Rate Limit: 60 requests/minute

Last Updated: 2025-07-10 12:00:00 UTC
```

---

## 🔧 **Configuration**

### **Environment Variables**

The CLI respects these environment variables:

```bash
# Database Configuration
DATABASE_URL="postgresql://user:pass@host:5432/authly"

# JWT Configuration
JWT_SECRET_KEY="your-secret-key"
JWT_REFRESH_SECRET_KEY="your-refresh-secret"

# Admin API Configuration
AUTHLY_ADMIN_API_ENABLED="true"
AUTHLY_ADMIN_API_URL="http://localhost:8000"

# Development
AUTHLY_DEV_MODE="true"
AUTHLY_LOG_LEVEL="DEBUG"
```

### **CLI Configuration File**

Create `~/.authly/config.toml` for persistent CLI settings:

```toml
[api]
url = "https://auth.mycompany.com"
timeout = 30

[auth]
auto_refresh = true
token_file = "~/.authly/tokens.json"

[output]
default_format = "table"
show_timestamps = true
```

### **Token Storage**

Admin tokens are securely stored in `~/.authly/tokens.json`:

```json
{
  "access_token": "encrypted_token_here",
  "refresh_token": "encrypted_refresh_token",
  "expires_at": "2025-07-10T15:30:00Z",
  "api_url": "http://localhost:8000"
}
```

**Security Features**:
- Tokens are encrypted using system keyring when available
- File permissions set to 600 (owner read/write only)
- Automatic token refresh before expiration
- Secure cleanup on logout

---

## 🛠️ **Advanced Usage**

### **Scripting & Automation**

#### **JSON Output for Scripts**
```bash
# Get client list in JSON format
clients=$(python -m authly admin client list --output json)
echo "$clients" | jq '.clients[].client_id'

# Create client and extract client_id
client_info=$(python -m authly admin client create \
  --name "Automated Client" \
  --type confidential \
  --redirect-uri "https://example.com/callback" \
  --output json)

client_id=$(echo "$client_info" | jq -r '.client_id')
echo "Created client: $client_id"
```

#### **Batch Operations**
```bash
#!/bin/bash
# Create multiple scopes
scopes=("read" "write" "delete" "admin")
descriptions=("Read access" "Write access" "Delete access" "Admin access")

for i in "${!scopes[@]}"; do
  python -m authly admin scope create \
    --name "${scopes[$i]}" \
    --description "${descriptions[$i]}"
done
```

### **CI/CD Integration**

#### **GitHub Actions Example**
```yaml
- name: Setup Authly Admin
  run: |
    # Non-interactive login for CI
    python -m authly admin login \
      --username "${{ secrets.AUTHLY_ADMIN_USER }}" \
      --password "${{ secrets.AUTHLY_ADMIN_PASS }}"
    
    # Create deployment client
    python -m authly admin client create \
      --name "Production Deploy" \
      --type confidential \
      --redirect-uri "${{ env.PRODUCTION_CALLBACK_URL }}" \
      --output json > client.json
```

### **Error Handling**

#### **Exit Codes**
- `0` - Success
- `1` - General error
- `2` - Authentication error
- `3` - Permission denied
- `4` - Resource not found
- `5` - Validation error

#### **Error Output**
```bash
$ python -m authly admin client show invalid-client
❌ Error: Client not found
Client ID 'invalid-client' does not exist or has been deleted.

Exit code: 4
```

### **Debugging**

#### **Verbose Mode**
```bash
# Enable verbose output
export AUTHLY_LOG_LEVEL=DEBUG
python -m authly admin status --verbose

# Show HTTP requests
export AUTHLY_DEBUG_HTTP=true
python -m authly admin client list
```

#### **API Connection Testing**
```bash
# Test API connectivity
python -m authly admin status

# Test authentication
python -m authly admin whoami

# Show detailed connection info
python -m authly admin status --verbose
```

---

## 🔒 **Security Considerations**

### **Token Security**
- Never share admin tokens or include them in scripts
- Use environment variables for automation
- Tokens automatically expire and refresh
- Logout clears all stored credentials

### **Production Usage**
- Use dedicated admin accounts, not your personal account
- Implement role-based access for admin operations
- Monitor admin API access through audit logs
- Restrict admin API to localhost or secure networks

### **Best Practices**
- Use `--confirm` flags in production scripts to avoid accidental changes
- Always verify operations with `--dry-run` when available
- Keep CLI tools updated for security patches
- Use JSON output for parsing to avoid format changes

---

This comprehensive CLI guide covers all administrative operations for the Authly OAuth 2.1 + OpenID Connect 1.0 authorization server. For API integration details, see the [API Reference](api-reference.md).