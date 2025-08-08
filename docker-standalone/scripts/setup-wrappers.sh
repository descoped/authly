#!/bin/sh
# Setup wrapper scripts for Authly standalone container
set -e

echo "Setting up wrapper scripts..."

# Create simple auth flow wrapper with runtime password patching
cat > /usr/local/bin/simple-auth-flow << 'EOF'
#!/bin/bash
cd /app

# Ensure LOG_LEVEL is set to avoid integer expression errors
export LOG_LEVEL="${LOG_LEVEL:-INFO}"

# Create a runtime-patched version of simple-auth-flow.sh
# The password will be set at runtime
ADMIN_PASSWORD="${AUTHLY_ADMIN_PASSWORD:-admin}"

# Create temporary patched script
cp /app/scripts/simple-auth-flow-original.sh /tmp/simple-auth-flow-patched.sh

# Apply comprehensive password fixes
# 1. Fix password for created users (must be 8+ chars)
sed -i 's/"password": "Test123!"/"password": "TestUser123!"/g' /tmp/simple-auth-flow-patched.sh

# 2. Fix admin-specific login attempts in OAuth token requests
sed -i "s/grant_type=password\&username=admin\&password=Test123%21/grant_type=password\&username=admin\&password=${ADMIN_PASSWORD}/g" /tmp/simple-auth-flow-patched.sh

# 3. Add a helper function to get the correct password for each user
cat > /tmp/patch_test_login.sh << 'PATCH'
#!/bin/bash
# Insert helper function before test_login
sed -i '/^test_login() {/i\
get_user_password() {\
    local user="$1"\
    if [ "$user" = "admin" ]; then\
        echo "'"${AUTHLY_ADMIN_PASSWORD:-admin}"'"\
    elif [ "$user" = "user1" ]; then\
        echo "Test123!"\
    else\
        echo "TestUser123!"\
    fi\
}' "$1"

# Replace the data line in test_login function ONLY (must be within function scope)
# Use a more specific pattern that only matches within the test_login function
sed -i '/^test_login() {/,/^}$/ s|data=$(printf.*grant_type=password.*Test123.*|    local user_password=$(get_user_password "$username")\n    data=$(printf "grant_type=password\&username=%s\&password=%s\&scope=openid%%20profile%%20email" "$username" "${user_password//!/%21}")|' "$1"
PATCH

chmod +x /tmp/patch_test_login.sh
/tmp/patch_test_login.sh /tmp/simple-auth-flow-patched.sh

# 4. Fix where NEW_USER tries to login (should use TestUser123!)
# This is in the main script body, not in a function, around line 620-621
# Handle both %21 and %%21 escaping patterns
sed -i '/Testing login before verification/,+3 s/Test123%%21/TestUser123%%21/' /tmp/simple-auth-flow-patched.sh

# 5. Fix the log level comparison to handle empty indices
# Add a default value to prevent integer expression errors
sed -i 's/if \[ "\$msg_level_index" -ge "\$current_level_index" \]/if [ "${msg_level_index:-0}" -ge "${current_level_index:-3}" ]/' /tmp/simple-auth-flow-patched.sh

# Run simple SQL-based pre-seed
/usr/local/bin/pre-seed-sql

# Execute the patched script
exec /bin/bash /tmp/simple-auth-flow-patched.sh "$@"
EOF

chmod +x /usr/local/bin/simple-auth-flow

# Create SQL-based pre-seed script
cat > /usr/local/bin/pre-seed-sql << 'EOF'
#!/bin/sh

# Function to check if test users exist
check_test_users() {
    # Wait for Authly to be ready
    timeout 30 sh -c 'until curl -s http://localhost:8000/health >/dev/null 2>&1; do sleep 1; done' || {
        echo "❌ Authly service not ready after 30 seconds"
        return 1
    }
    
    # Test admin login with environment password (set at runtime)
    admin_password=${AUTHLY_ADMIN_PASSWORD:-admin}
    admin_response=$(curl -s -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password&username=admin&password=${admin_password}" \
        http://localhost:8000/api/v1/oauth/token 2>/dev/null)
    
    # Test user1 login with Test123! password
    user1_response=$(curl -s -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password&username=user1&password=Test123%21" \
        http://localhost:8000/api/v1/oauth/token 2>/dev/null)
    
    if echo "$admin_response" | grep -q "access_token" && echo "$user1_response" | grep -q "access_token"; then
        return 0  # Both users exist with correct passwords
    else
        return 1  # Need to seed user1
    fi
}

# Function to seed user1 via direct SQL and fix admin for testing
seed_user1_sql() {
    echo "🌱 Preparing test users for simple-auth-flow..."
    
    # Generate bcrypt hash for "Test123!" password (cost factor 12)
    USER1_PASSWORD_HASH=$(python3 -c "
import bcrypt
print(bcrypt.hashpw(b'Test123!', bcrypt.gensalt()).decode())
" 2>/dev/null)
    
    if [ -z "$USER1_PASSWORD_HASH" ]; then
        echo "❌ Failed to generate password hash"
        return 1
    fi
    
    # Fix admin user for testing (remove password change requirement) and create user1
    PGPASSWORD=authly psql -h localhost -U authly -d authly -q -c "
        -- Remove password change requirement from admin for testing
        UPDATE users 
        SET requires_password_change = false 
        WHERE username = 'admin';
        
        -- Insert user1 
        INSERT INTO users (
            id, username, email, password_hash, 
            created_at, updated_at, 
            is_active, is_verified, is_admin, requires_password_change
        ) VALUES (
            gen_random_uuid(), 'user1', 'user1@example.com', '$USER1_PASSWORD_HASH',
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
            true, true, false, false
        ) 
        ON CONFLICT (username) DO NOTHING;
    " >/dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo "✅ Test users ready (admin password change requirement removed)"
        return 0
    else
        echo "❌ Failed to prepare test users"
        return 1
    fi
}

# Main logic - Check if help is requested
for arg in "$@"; do
    case "$arg" in
        -h|--help)
            # Don't interfere with help
            exit 0
            ;;
    esac
done

# Check if test users exist
if ! check_test_users; then
    admin_password=${AUTHLY_ADMIN_PASSWORD:-admin}
    echo ""
    echo "⚠️  Simple-auth-flow requires user1 for comprehensive testing"
    echo ""
    echo "This will create the following test account:"
    echo "  • user1 (password: Test123!)"
    echo "  • admin (password: ${admin_password}) - already exists"
    echo ""
    printf "Do you want to create user1? [y/N]: "
    read -r answer
    echo ""
    
    case "$answer" in
        [Yy]|[Yy][Ee][Ss])
            if seed_user1_sql; then
                echo "✅ Test users are ready!"
                echo ""
            else
                echo "❌ Failed to create user1"
                echo "Some simple-auth-flow tests may fail"
                echo ""
            fi
            ;;
        *)
            echo "⚠️  Continuing without user1"
            echo "Some simple-auth-flow tests will likely fail"
            echo ""
            ;;
    esac
fi

exit 0
EOF

chmod +x /usr/local/bin/pre-seed-sql

# Create integration test wrapper
cat > /usr/local/bin/authly-test << 'EOF'
#!/bin/sh
cd /app
exec /app/scripts/run-integration-tests.sh "$@"
EOF

chmod +x /usr/local/bin/authly-test

# Create run-end-to-end-test wrapper
cat > /usr/local/bin/run-end-to-end-test << 'EOF'
#!/bin/sh
cd /app
exec /app/scripts/run-integration-tests.sh "$@"
EOF

chmod +x /usr/local/bin/run-end-to-end-test

# Create unlock-admin-account wrapper
cat > /usr/local/bin/unlock-admin-account << 'EOF'
#!/bin/sh
exec /app/scripts/unlock-admin-account.sh "$@"
EOF

chmod +x /usr/local/bin/unlock-admin-account

echo "✅ Wrapper scripts created"