#!/bin/bash
# Unlock Admin Account Script
# Purpose: Directly reset and unlock the admin account in standalone container
# Usage: unlock-admin-account [username]

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get admin username from argument or environment
ADMIN_USER="${1:-${AUTHLY_ADMIN_USERNAME:-admin}}"

echo -e "${YELLOW}Unlock Admin Account${NC}"
echo "================================="
echo "Admin username: $ADMIN_USER"
echo ""

# Check if we're in standalone mode
if [ "$AUTHLY_STANDALONE" != "true" ]; then
    echo -e "${YELLOW}Warning: Not in standalone mode. This script is intended for standalone containers.${NC}"
    echo "Continue anyway? (y/N)"
    read -r response
    if [ "$response" != "y" ] && [ "$response" != "Y" ]; then
        echo "Aborted."
        exit 1
    fi
fi

# Database connection details (from standalone environment)
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-authly}"
DB_USER="${DB_USER:-authly}"
DB_PASS="${DB_PASS:-authly}"

# Connect to PostgreSQL and reset admin account
echo -e "${YELLOW}Connecting to database...${NC}"

PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
-- Force enable admin account
WITH updated AS (
    UPDATE users 
    SET 
        is_active = true,
        is_verified = true,
        requires_password_change = false,
        last_login = CURRENT_TIMESTAMP
    WHERE username = '$ADMIN_USER'
    RETURNING username
)
SELECT 
    CASE 
        WHEN COUNT(*) > 0 THEN 'SUCCESS: Admin account unlocked'
        ELSE 'WARNING: No user found with username $ADMIN_USER'
    END as result
FROM updated;

-- Show current admin status
SELECT 
    username,
    email,
    is_active,
    is_verified,
    is_admin,
    requires_password_change,
    last_login,
    created_at
FROM users 
WHERE username = '$ADMIN_USER';
EOF

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ Admin account '$ADMIN_USER' has been unlocked in database!${NC}"
    echo ""
    echo "The account is now:"
    echo "  • Active (is_active = true)"
    echo "  • Verified (is_verified = true)"  
    echo "  • No password change required"
    echo ""
    
    # Restart Authly service to clear in-memory lockout state
    if [ "$AUTHLY_STANDALONE" = "true" ]; then
        echo -e "${YELLOW}Restarting Authly service to clear in-memory lockout state...${NC}"
        
        # Kill the Python process to force a complete restart (clears all memory state)
        pkill -f "python.*authly" 2>/dev/null || true
        
        # Give s6 a moment to detect the process is gone and restart it
        echo "Waiting for Authly to restart..."
        sleep 5
        
        # Wait for service to come back up (with timeout)
        ATTEMPTS=0
        MAX_ATTEMPTS=30
        while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
            if curl -s http://localhost:8000/health 2>/dev/null | grep -q "healthy"; then
                echo -e "${GREEN}✅ Authly service restarted successfully${NC}"
                break
            fi
            ATTEMPTS=$((ATTEMPTS + 1))
            sleep 1
        done
        
        if [ $ATTEMPTS -eq $MAX_ATTEMPTS ]; then
            echo -e "${YELLOW}⚠️  Authly service is taking longer than expected to restart...${NC}"
            echo "You may need to wait a few more seconds before attempting to login."
        fi
    else
        echo -e "${YELLOW}Note: Not in standalone mode. You may need to manually restart the Authly service to clear in-memory lockout state.${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}Admin account is now ready for login!${NC}"
    echo "Note: This bypassed all lockout mechanisms."
else
    echo ""
    echo -e "${RED}✗ Failed to update admin account${NC}"
    echo "Check database connection and credentials."
    exit 1
fi