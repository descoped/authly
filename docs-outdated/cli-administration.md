# Authly Admin CLI Usage Guide

The Authly Admin CLI provides comprehensive command-line tools for managing OAuth 2.1 clients and scopes in your Authly instance.

## Installation

The CLI is automatically available after installing Authly:

```bash
# Install Authly with Poetry
poetry install

# The CLI is now available as
authly-admin --help
```

## Configuration

The CLI uses the same configuration as the main Authly application. Set your database connection and other settings using environment variables or a configuration file.

### Environment Variables

```bash
export DATABASE_URL="postgresql://username:password@localhost:5432/authly"
export JWT_SECRET_KEY="your-secret-key"
export JWT_REFRESH_SECRET_KEY="your-refresh-secret-key"
```

### Configuration File

Alternatively, use a configuration file:

```bash
authly-admin --config /path/to/config.toml client list
```

## Global Options

- `--config PATH`: Path to configuration file
- `--verbose`, `-v`: Enable verbose output
- `--dry-run`: Show what would be done without executing
- `--help`: Show help information

## OAuth Client Management

### Create a Client

```bash
# Create a public OAuth client (for mobile/SPA apps)
authly-admin client create \
  --name "My Mobile App" \
  --type public \
  --redirect-uri "https://myapp.com/callback" \
  --scope "read write"

# Create a confidential OAuth client (for server apps)
authly-admin client create \
  --name "My Server App" \
  --type confidential \
  --redirect-uri "https://myapp.com/callback" \
  --redirect-uri "https://myapp.com/admin/callback" \
  --scope "read write admin" \
  --auth-method client_secret_basic
```

### List Clients

```bash
# List all active clients
authly-admin client list

# List clients with pagination
authly-admin client list --limit 10 --offset 0

# Include inactive clients
authly-admin client list --show-inactive

# JSON output format
authly-admin client list --output json
```

### Show Client Details

```bash
# Show detailed client information
authly-admin client show "your-client-id"

# JSON output format
authly-admin client show "your-client-id" --output json
```

### Update a Client

```bash
# Update client name
authly-admin client update "your-client-id" --name "Updated App Name"

# Update multiple properties
authly-admin client update "your-client-id" \
  --name "New Name" \
  --client-uri "https://newdomain.com" \
  --logo-uri "https://newdomain.com/logo.png"

# Deactivate a client
authly-admin client update "your-client-id" --deactivate

# Reactivate a client
authly-admin client update "your-client-id" --activate
```

### Regenerate Client Secret

```bash
# Regenerate secret for confidential clients
authly-admin client regenerate-secret "your-client-id"

# Skip confirmation prompt
authly-admin client regenerate-secret "your-client-id" --confirm
```

### Delete a Client

```bash
# Deactivate a client (soft delete)
authly-admin client delete "your-client-id"

# Skip confirmation prompt
authly-admin client delete "your-client-id" --confirm
```

## OAuth Scope Management

### Create a Scope

```bash
# Create a basic scope
authly-admin scope create \
  --name "read" \
  --description "Read access to user data"

# Create a default scope (granted automatically)
authly-admin scope create \
  --name "profile" \
  --description "Access to user profile information" \
  --default
```

### List Scopes

```bash
# List all active scopes
authly-admin scope list

# Show only default scopes
authly-admin scope list --default-only

# Include inactive scopes
authly-admin scope list --show-inactive

# JSON output format
authly-admin scope list --output json
```

### Show Scope Details

```bash
# Show detailed scope information
authly-admin scope show "read"

# JSON output format
authly-admin scope show "read" --output json
```

### Update a Scope

```bash
# Update scope description
authly-admin scope update "read" --description "Updated description"

# Make a scope default
authly-admin scope update "read" --make-default

# Remove default flag
authly-admin scope update "read" --remove-default

# Deactivate a scope
authly-admin scope update "read" --deactivate
```

### Delete a Scope

```bash
# Deactivate a scope (soft delete)
authly-admin scope delete "read"

# Skip confirmation prompt
authly-admin scope delete "read" --confirm
```

### Show Default Scopes

```bash
# List all default scopes
authly-admin scope defaults

# JSON output format
authly-admin scope defaults --output json
```

## System Status

### Check Instance Status

```bash
# Basic status check
authly-admin status

# Verbose status with configuration details
authly-admin --verbose status
```

## Advanced Usage

### Dry Run Mode

Use `--dry-run` to preview changes without executing them:

```bash
# Preview client creation
authly-admin --dry-run client create \
  --name "Test Client" \
  --type public \
  --redirect-uri "https://example.com/callback"

# Preview scope updates
authly-admin --dry-run scope update "read" --description "New description"
```

### JSON Output

Many commands support `--output json` for programmatic usage:

```bash
# Get client data in JSON format
authly-admin client show "client-id" --output json

# Pipe to jq for processing
authly-admin client list --output json | jq '.[] | .client_name'
```

### Batch Operations

Create multiple clients or scopes using shell scripts:

```bash
#!/bin/bash
# Create multiple test clients
for i in {1..5}; do
  authly-admin client create \
    --name "Test Client $i" \
    --type public \
    --redirect-uri "https://test$i.example.com/callback"
done
```

## Examples

### Setting Up a Complete OAuth Environment

```bash
# 1. Create scopes
authly-admin scope create --name "read" --description "Read access" --default
authly-admin scope create --name "write" --description "Write access"
authly-admin scope create --name "admin" --description "Administrative access"

# 2. Create a web application client
authly-admin client create \
  --name "Web Application" \
  --type confidential \
  --redirect-uri "https://webapp.example.com/auth/callback" \
  --scope "read write" \
  --client-uri "https://webapp.example.com" \
  --auth-method client_secret_basic

# 3. Create a mobile application client
authly-admin client create \
  --name "Mobile App" \
  --type public \
  --redirect-uri "https://mobileapp.example.com/callback" \
  --redirect-uri "com.example.mobileapp://callback" \
  --scope "read"

# 4. Check the setup
authly-admin client list
authly-admin scope list
authly-admin status
```

### Client Management Workflow

```bash
# 1. Create a new client
CLIENT_ID=$(authly-admin client create \
  --name "New Service" \
  --type confidential \
  --redirect-uri "https://service.example.com/callback" \
  --output json | jq -r '.client_id')

# 2. Show the created client
authly-admin client show "$CLIENT_ID"

# 3. Update client information
authly-admin client update "$CLIENT_ID" \
  --client-uri "https://service.example.com" \
  --logo-uri "https://service.example.com/logo.png"

# 4. Regenerate client secret if needed
authly-admin client regenerate-secret "$CLIENT_ID" --confirm

# 5. Deactivate when no longer needed
authly-admin client delete "$CLIENT_ID" --confirm
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**: Ensure your `DATABASE_URL` is correct and the database is running.

2. **Permission Denied**: Make sure your database user has the necessary permissions.

3. **Client Not Found**: Verify the client ID is correct using `authly-admin client list`.

4. **Invalid Configuration**: Check your environment variables or configuration file.

### Debug Mode

Use verbose mode to see detailed information:

```bash
authly-admin --verbose client create --name "Debug Client" --type public --redirect-uri "https://example.com"
```

### Configuration Check

Verify your setup with the status command:

```bash
authly-admin --verbose status
```

This will show:
- Database connection status
- Configuration details
- Quick statistics about clients and scopes

## Security Considerations

1. **Client Secrets**: Store client secrets securely and regenerate them periodically.

2. **Scope Design**: Use granular scopes following the principle of least privilege.

3. **Client Types**: 
   - Use `confidential` for server-side applications that can securely store secrets
   - Use `public` for mobile/SPA applications that cannot securely store secrets

4. **PKCE**: Always use PKCE for public clients (enabled by default).

5. **Redirect URIs**: Use HTTPS for production redirect URIs and validate them carefully.

## Integration with CI/CD

The CLI can be used in CI/CD pipelines for automated OAuth client management:

```yaml
# Example GitHub Actions workflow
name: Deploy OAuth Clients
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - name: Install Authly
        run: pip install authly
      - name: Deploy clients
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
        run: |
          authly-admin client create \
            --name "Production App" \
            --type confidential \
            --redirect-uri "https://prod.example.com/callback"
```

For more information, see the main Authly documentation.