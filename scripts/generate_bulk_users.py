#!/usr/bin/env python3
"""
Bulk user generator for performance testing.

This script generates a large number of test users and associated tokens/sessions
to test the performance of admin queries with realistic datasets in a Greenfield project.
This is specifically designed for testing optimized CTE-based queries implemented in Increment 5.1.
"""

import asyncio
import logging
import secrets
import string
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from authly.auth.core import get_password_hash
from authly.core.config import get_config
from authly.core.database import create_database_connection
from authly.tokens.models import TokenModel, TokenType
from authly.tokens.repository import TokenRepository
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


class BulkUserGenerator:
    """Generator for bulk test users and sessions."""

    def __init__(self):
        self.locales = ["en-US", "en-GB", "fr-FR", "de-DE", "es-ES", "it-IT", "pt-BR", "ja-JP", "ko-KR", "zh-CN"]
        self.timezones = [
            "America/New_York",
            "America/Los_Angeles",
            "Europe/London",
            "Europe/Paris",
            "Europe/Berlin",
            "Asia/Tokyo",
            "Asia/Seoul",
            "Australia/Sydney",
        ]
        self.domains = ["example.com", "test.org", "demo.net", "sample.co", "mock.io"]

    def generate_random_string(self, length: int) -> str:
        """Generate a random string of given length."""
        return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(length))

    def generate_user_data(self, index: int) -> dict:
        """Generate realistic user data."""
        base_username = f"user_{index:06d}_{self.generate_random_string(4)}"
        domain = secrets.choice(self.domains)

        # Generate some variety in user attributes
        is_active = secrets.randbelow(100) < 95  # 95% active users
        is_verified = secrets.randbelow(100) < 90  # 90% verified users
        is_admin = secrets.randbelow(1000) < 5  # 0.5% admin users
        requires_password_change = secrets.randbelow(100) < 10  # 10% need password change

        # Generate realistic creation dates (spread over last 2 years)
        days_ago = secrets.randbelow(730)  # 0-2 years ago
        created_at = datetime.now(UTC) - timedelta(days=days_ago)

        # Last login (70% have logged in recently)
        last_login = None
        if secrets.randbelow(100) < 70:
            login_days_ago = secrets.randbelow(min(days_ago, 30))  # Logged in within last 30 days
            last_login = datetime.now(UTC) - timedelta(days=login_days_ago)

        return {
            "id": uuid4(),
            "username": base_username,
            "email": f"{base_username}@{domain}",
            "password_hash": get_password_hash("TestPassword123!"),
            "given_name": f"User{index:06d}",
            "family_name": f"Surname{secrets.randbelow(1000):03d}",
            "locale": secrets.choice(self.locales),
            "zoneinfo": secrets.choice(self.timezones),
            "created_at": created_at,
            "updated_at": created_at,
            "last_login": last_login,
            "is_active": is_active,
            "is_verified": is_verified,
            "is_admin": is_admin,
            "requires_password_change": requires_password_change,
        }

    async def create_users_batch(self, user_repo: UserRepository, batch_data: list[dict]) -> int:
        """Create a batch of users efficiently."""
        created_count = 0
        for user_data in batch_data:
            try:
                user = UserModel(**user_data)
                await user_repo.create(user)
                created_count += 1
            except Exception as e:
                logger.warning(f"Failed to create user {user_data['username']}: {e}")
        return created_count

    async def create_sessions_for_users(
        self, token_repo: TokenRepository, user_ids: list[str], sessions_per_user: int
    ) -> int:
        """Create test sessions (tokens) for users."""
        created_count = 0

        for user_id in user_ids:
            # Create varying numbers of sessions per user
            num_sessions = secrets.randbelow(sessions_per_user) + 1

            for _ in range(num_sessions):
                try:
                    # Create access token
                    access_token = TokenModel(
                        id=uuid4(),
                        user_id=user_id,
                        token_jti=f"jti_{uuid4().hex}",
                        token_value=f"access_{self.generate_random_string(32)}",
                        token_type=TokenType.ACCESS,
                        expires_at=datetime.now(UTC) + timedelta(hours=1),
                        created_at=datetime.now(UTC),
                        invalidated=False,
                        scope="openid profile email",
                    )
                    await token_repo.store_token(access_token)

                    # Create refresh token
                    refresh_token = TokenModel(
                        id=uuid4(),
                        user_id=user_id,
                        token_jti=f"jti_{uuid4().hex}",
                        token_value=f"refresh_{self.generate_random_string(32)}",
                        token_type=TokenType.REFRESH,
                        expires_at=datetime.now(UTC) + timedelta(days=30),
                        created_at=datetime.now(UTC),
                        invalidated=False,
                        scope="openid profile email",
                    )
                    await token_repo.store_token(refresh_token)

                    created_count += 2
                except Exception as e:
                    logger.warning(f"Failed to create tokens for user {user_id}: {e}")

        return created_count

    async def generate_bulk_data(self, total_users: int, batch_size: int = 1000, sessions_per_user: int = 3):
        """Generate bulk users and sessions for performance testing."""
        config = get_config()

        logger.info(f"Starting bulk data generation: {total_users} users, batch size {batch_size}")
        start_time = time.time()

        async with create_database_connection(config.database_url) as conn:
            user_repo = UserRepository(conn)
            token_repo = TokenRepository(conn)

            total_created_users = 0
            total_created_tokens = 0
            user_ids_for_sessions = []

            # Generate users in batches
            for batch_start in range(0, total_users, batch_size):
                batch_end = min(batch_start + batch_size, total_users)
                batch_number = (batch_start // batch_size) + 1
                total_batches = (total_users + batch_size - 1) // batch_size

                logger.info(f"Processing batch {batch_number}/{total_batches} (users {batch_start + 1}-{batch_end})")

                # Generate batch data
                batch_data = []
                batch_user_ids = []

                for i in range(batch_start, batch_end):
                    user_data = self.generate_user_data(i)
                    batch_data.append(user_data)
                    batch_user_ids.append(str(user_data["id"]))

                # Create users
                async with conn.transaction():
                    created_users = await self.create_users_batch(user_repo, batch_data)
                    total_created_users += created_users

                    # Collect user IDs for session creation
                    user_ids_for_sessions.extend(batch_user_ids[:created_users])

                logger.info(f"Batch {batch_number}: Created {created_users} users")

            # Create sessions for users (in batches to avoid memory issues)
            logger.info("Creating sessions for users...")
            session_batch_size = 500

            for i in range(0, len(user_ids_for_sessions), session_batch_size):
                batch_user_ids = user_ids_for_sessions[i : i + session_batch_size]

                async with conn.transaction():
                    created_tokens = await self.create_sessions_for_users(token_repo, batch_user_ids, sessions_per_user)
                    total_created_tokens += created_tokens

                logger.info(f"Created sessions for {len(batch_user_ids)} users ({created_tokens} tokens)")

        end_time = time.time()
        duration = end_time - start_time

        logger.info(f"""
Bulk data generation completed!
- Total users created: {total_created_users}
- Total tokens created: {total_created_tokens}
- Duration: {duration:.2f} seconds
- Users per second: {total_created_users / duration:.2f}
- Tokens per second: {total_created_tokens / duration:.2f}
        """)


async def main():
    """Main function."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Parse command line arguments
    import argparse

    parser = argparse.ArgumentParser(description="Generate bulk users for performance testing")
    parser.add_argument("--users", type=int, default=10000, help="Number of users to generate (default: 10000)")
    parser.add_argument("--batch-size", type=int, default=1000, help="Batch size for user creation (default: 1000)")
    parser.add_argument("--sessions", type=int, default=3, help="Average sessions per user (default: 3)")

    args = parser.parse_args()

    generator = BulkUserGenerator()
    await generator.generate_bulk_data(
        total_users=args.users, batch_size=args.batch_size, sessions_per_user=args.sessions
    )


if __name__ == "__main__":
    asyncio.run(main())
