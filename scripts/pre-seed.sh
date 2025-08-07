#!/bin/bash
# Pre-seed script for simple-auth-flow  
# Creates test users needed for the simple-auth-flow script to work properly

# Function to check if test users exist 
check_test_users() {
    # Wait for Authly to be ready
    timeout 30 sh -c 'until curl -s http://localhost:8000/health >/dev/null 2>&1; do sleep 1; done' || {
        echo "❌ Authly service not ready after 30 seconds"
        return 1
    }
    
    # Test admin login with environment password
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

# Function to seed user1 only (leave admin alone)
seed_user1() {
    cat > /tmp/seed_user1.py << 'EOF'
import asyncio
import sys
import os
from datetime import UTC, datetime
from uuid import uuid4

# Add the app directory to Python path
sys.path.insert(0, '/app')

from authly.auth import get_password_hash
from authly.users import UserModel, UserRepository
from psycopg_pool import AsyncConnectionPool

async def seed_user1():
    """Seed user1 only (leave admin bootstrap user alone)"""
    try:
        # Connect directly to PostgreSQL using DATABASE_URL
        database_url = os.getenv('DATABASE_URL', 'postgresql://authly:authly@localhost/authly')
        
        # Create connection pool with proper async initialization
        pool = AsyncConnectionPool(database_url)
        await pool.open()
        
        async with pool.connection() as connection:
            user_repo = UserRepository(connection)
            
            # Create only user1 (admin exists from bootstrap)
            user_data = {
                "username": "user1", 
                "email": "user1@example.com",
                "password": "Test123!",
                "is_admin": False,
            }

            # Check if user already exists by username
            existing_user = await user_repo.get_by_username(user_data["username"])
            if not existing_user:
                user = UserModel(
                    id=uuid4(),
                    username=user_data["username"],
                    email=user_data["email"],
                    password_hash=get_password_hash(user_data["password"]),
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                    is_active=True,
                    is_verified=True,
                    is_admin=bool(user_data["is_admin"]),
                )
                await user_repo.create(user)
                print(f"Created user: {user.username}")
                return True
            else:
                print(f"User {user_data['username']} already exists")
                return True
        
    except Exception as e:
        print(f"Error seeding user1: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False
    finally:
        if 'pool' in locals():
            await pool.close()

if __name__ == "__main__":
    result = asyncio.run(seed_user1())
    sys.exit(0 if result else 1)
EOF

    if python /tmp/seed_user1.py; then
        rm -f /tmp/seed_user1.py
        return 0
    else
        rm -f /tmp/seed_user1.py
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
            echo "🌱 Creating user1..."
            if seed_user1; then
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