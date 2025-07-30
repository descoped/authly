# Authly CLI Administration Guide

Complete command-line interface guide for administering the Authly OAuth 2.1 + OpenID Connect 1.0 authorization server.

**CLI Access**: `python -m authly`  
**Admin Commands**: `python -m authly admin`  
**Architecture**: API-first (CLI uses HTTP API exclusively)  
**Resource Mode**: Unified resource manager with `AUTHLY_MODE=cli` for optimal performance

> **💡 Virtual Environment Usage**  
> - **With `uv run`**: Automatically sources the virtual environment (`.venv/bin/activate`) - **recommended for simplicity**
> - **Manual activation**: Run `source .venv/bin/activate` first, then use `python -m authly` commands directly
> - All examples in this guide use `uv run` for consistency and ease of use

---

## 🚀 **Quick Start**

### **Installation & Setup**
```bash
# Install Authly (all groups including test/dev with forced update)
uv sync --all-groups -U

# Start Authly server (embedded development mode)
uv run python -m authly serve --embedded

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
  --client-type confidential \
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

## ⚙️ **How CLI Mode Works**

### **Unified Resource Manager Architecture**

The Authly CLI uses a unified resource manager architecture that automatically optimizes for administrative operations:

```python
# CLI mode automatically configured when running admin commands
AUTHLY_MODE=cli python -m authly admin status
```

**CLI Mode Characteristics**:

| Feature | CLI Mode | Production Mode | Embedded Mode |
|---------|----------|-----------------|---------------|
| **Pool Size** | 1-3 connections | 5-20 connections | 2-8 connections |
| **Timeout** | 10s | 30s | 15s |
| **Idle Time** | 1 minute | 5 minutes | 3 minutes |
| **Bootstrap** | Disabled | Environment controlled | Always enabled |
| **Lifecycle** | Context-managed | FastAPI lifespan | Self-contained |

### **Resource Optimization**

CLI mode provides several optimizations for administrative workflows:

1. **Minimal Resource Usage**: Small connection pool optimized for short operations
2. **Fast Cleanup**: Resources automatically cleaned up after each command
3. **No Bootstrap Overhead**: Skips admin bootstrap (assumes existing setup)
4. **Quick Timeouts**: Optimized for interactive CLI usage

### **Mode Detection & Override**

The CLI automatically detects and sets optimal resource mode:

```bash
# Automatic CLI mode (recommended)
python -m authly admin client list

# Manual override (advanced usage)
AUTHLY_MODE=production python -m authly admin status  # Uses production settings
AUTHLY_MODE=testing python -m authly admin status     # Uses testing settings
```

**Mode Aliases Supported**:
- `cli`, `admin` → CLI mode
- `production`, `prod` → Production mode  
- `embedded`, `embed`, `dev`, `development` → Embedded mode
- `testing`, `test` → Testing mode

### **Database Connection Management**

CLI mode uses context-managed database connections:

```python
# Simplified connection lifecycle for CLI operations
async with resource_manager.get_database().connection() as conn:
    # Execute admin operation
    result = await admin_operation(conn)
    # Connection automatically cleaned up
```

**Connection Pool Settings** (CLI Mode):
```python
{
    "min_size": 1,        # Minimal baseline
    "max_size": 3,        # Small pool for CLI ops
    "timeout": 10.0,      # Quick connection timeout
    "max_idle": 60.0,     # 1 minute idle timeout
    "reconnect_timeout": 1.0  # Fast reconnection
}
```

---

## 🌐 **Server Commands**

### **Start Authly Server**

#### **python -m authly serve**
Start the Authly web service.

**Options**:
```bash
--host TEXT                     Host to bind to (default: 0.0.0.0)
--port INTEGER                  Port to bind to (default: 8000)
--workers INTEGER               Number of worker processes (default: 1)
--embedded                      Run with embedded PostgreSQL container
--seed                          Seed test data (only with --embedded)
--log-level TEXT                Logging level (default: info)
--access-log / --no-access-log  Enable/disable access logging (default: enabled)
```

**Examples**:
```bash
# Production server
python -m authly serve --host 0.0.0.0 --port 8000

# Development with embedded database
python -m authly serve --embedded

# Development with embedded database and test data
python -m authly serve --embedded --seed

# Multi-worker production
python -m authly serve --workers 4

# Custom logging
python -m authly serve --log-level debug --no-access-log
```

**Environment Variables**:
```bash
# Resource Mode (automatically optimizes for CLI usage)
AUTHLY_MODE="cli"

# Database Configuration
DATABASE_URL="postgresql://user:pass@host:5432/authly"

# JWT Configuration
JWT_SECRET_KEY="your-secret-key"
JWT_REFRESH_SECRET_KEY="your-refresh-secret"

# Admin API Configuration (for CLI communication)
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
✓ Token expires: 2025-07-30 15:30:00 UTC
✓ Scopes: admin:clients:read, admin:clients:write, admin:scopes:read, admin:scopes:write
```

#### **python -m authly admin auth refresh**
Refresh authentication tokens.

```bash
$ python -m authly admin auth refresh
✓ Token refreshed successfully
New expiration: 2025-07-30 16:30:00 UTC
Token verified - authentication active
```

#### **python -m authly admin auth status**
Show authentication and API status.

```bash
$ python -m authly admin auth status
✓ API Health: healthy
API URL: http://localhost:8000
✓ Authentication: Logged in
Database: Connected
OAuth clients: 2
OAuth scopes: 17
```

**Options**:
```bash
--verbose, -v    Show detailed token information
```

**Examples**:
```bash
# Basic auth status
python -m authly admin auth status

# Detailed auth status with token info
python -m authly admin auth status --verbose
```

### **Authentication Command Group**

All authentication commands are also available through the `auth` subgroup for organized access:

#### **python -m authly admin auth [COMMAND]**

**Available Commands**:
```bash
login    Login to the Authly Admin API
logout   Logout from the Authly Admin API  
whoami   Show current authentication status
status   Show authentication and API status
refresh  Refresh authentication tokens
```

**Examples**:
```bash
# These commands are equivalent to the direct admin aliases:
python -m authly admin auth login     # Same as: python -m authly admin login
python -m authly admin auth logout    # Same as: python -m authly admin logout
python -m authly admin auth whoami    # Same as: python -m authly admin whoami

# Additional auth-specific commands:
python -m authly admin auth status    # Authentication and API status
python -m authly admin auth refresh   # Refresh authentication tokens
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
  --client-type confidential \
  --redirect-uri "https://myapp.com/callback"

# Public client with multiple redirect URIs
python -m authly admin client create \
  --name "My Mobile App" \
  --client-type public \
  --redirect-uri "myapp://callback" \
  --redirect-uri "http://localhost:3000/callback"

# Client with metadata and scopes
python -m authly admin client create \
  --name "Enterprise App" \
  --client-type confidential \
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

### **Unified Resource Manager**

The CLI uses Authly's unified resource manager architecture with optimal settings for admin operations:

```bash
# Resource Mode - Automatically optimizes for CLI usage
AUTHLY_MODE="cli"              # Triggers CLI-optimized resource management
```

**CLI Mode Features**:
- **Minimal Database Pool**: 1-3 connections optimized for short-lived operations
- **Context-Managed Lifecycle**: Resources cleaned up after each command
- **No Bootstrap**: Assumes existing admin system setup
- **Fast Timeout**: 10s timeout, 1min idle for quick operations

### **Environment Variables**

The CLI respects these environment variables:

```bash
# Resource Management
AUTHLY_MODE="cli"              # Enables CLI-optimized resource management

# Database Configuration
DATABASE_URL="postgresql://user:pass@host:5432/authly"

# JWT Configuration  
JWT_SECRET_KEY="your-secret-key"
JWT_REFRESH_SECRET_KEY="your-refresh-secret"

# Admin API Configuration
AUTHLY_ADMIN_API_ENABLED="true"
AUTHLY_ADMIN_API_URL="http://localhost:8000"

# Development & Debugging
AUTHLY_DEV_MODE="true"
AUTHLY_LOG_LEVEL="DEBUG"
```

### **Resource Mode Detection**

The CLI automatically sets `AUTHLY_MODE=cli` when running admin commands:

```bash
# These commands automatically use CLI mode
python -m authly admin login
python -m authly admin client list
python -m authly admin status

# Manual mode override (advanced usage)
AUTHLY_MODE=production python -m authly admin status
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
  --client-type confidential \
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
      --client-type confidential \
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

#### **Resource Manager Debugging**
```bash
# Enable verbose output with resource manager details
export AUTHLY_LOG_LEVEL=DEBUG
python -m authly admin status --verbose

# Show resource mode detection
python -c "
from authly.core.mode_factory import AuthlyModeFactory
print(f'Detected mode: {AuthlyModeFactory.detect_mode()}')
print(f'CLI mode check: {AuthlyModeFactory.is_cli_mode()}')
"

# Show HTTP requests
export AUTHLY_DEBUG_HTTP=true
python -m authly admin client list
```

#### **CLI Mode Testing**
```bash
# Test CLI mode resource management
AUTHLY_MODE=cli python -m authly admin status

# Compare with other modes (requires running server)
AUTHLY_MODE=production python -m authly admin status
AUTHLY_MODE=embedded python -m authly admin status

# Force different pool settings for testing
AUTHLY_MODE=testing python -m authly admin status --verbose
```

#### **API Connection Testing**
```bash
# Test API connectivity with CLI mode
python -m authly admin status

# Test authentication with resource manager info
python -m authly admin whoami

# Show detailed connection and resource info
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

## 🛠️ **CLI Mode Troubleshooting**

### **Common Issues & Solutions**

#### **Database Connection Issues**
```bash
# Check CLI mode is using correct database
AUTHLY_LOG_LEVEL=DEBUG python -m authly admin status

# Test with different pool settings
AUTHLY_MODE=testing python -m authly admin status  # Larger pool for testing
```

#### **Resource Manager Issues**
```bash
# Verify mode detection
python -c "
from authly.core.mode_factory import AuthlyModeFactory
print(f'Current mode: {AuthlyModeFactory.detect_mode()}')
print(f'Pool settings: {AuthlyModeFactory.get_pool_settings(AuthlyModeFactory.detect_mode())}')
"

# Force CLI mode explicitly
AUTHLY_MODE=cli python -m authly admin client list
```

#### **Admin API Connection Issues**
```bash
# Check if admin API is enabled on the server
curl -s http://localhost:8000/admin/health | jq

# Test with verbose logging
AUTHLY_LOG_LEVEL=DEBUG python -m authly admin status --verbose
```

### **Performance Optimization**

For frequent CLI operations, consider these optimizations:

```bash
# Use CLI mode for optimal performance
export AUTHLY_MODE=cli

# Batch operations in scripts
python -m authly admin client list --output json | jq '.clients[].client_id'

# Use connection pooling benefits
# CLI mode maintains connections for up to 1 minute for rapid successive commands
```

### **Development vs Production CLI Usage**

| Scenario | Recommended Mode | Reason |
|----------|------------------|---------|
| **Local Development** | `cli` | Optimized for quick admin tasks |
| **Production Admin** | `production` | Uses same settings as server |
| **CI/CD Scripts** | `cli` or `testing` | Fast, minimal resource usage |
| **Debugging** | `testing` | Larger pool, detailed logging |

---

This comprehensive CLI guide covers all administrative operations for the Authly OAuth 2.1 + OpenID Connect 1.0 authorization server, including the unified resource manager architecture and CLI mode optimizations. For API integration details, see the [API Reference](api-reference.md).