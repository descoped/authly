import pytest

from authly.auth import get_password_hash, verify_password


@pytest.mark.parametrize(
    "password_hash",
    [
        "$2b$12$MVS6KwDsWY3jlc3u4Y1Mw.xzSgRyMpy5Yp9xj6kUmqob1X8VitiCi",  # generated from bcrypt
        "$2b$12$W6WQdp9ioDLkqVbPNx7Bc.hh9Zj4jiw1UAgDeezbn7xOLyGlrZOwC",  # generated from bcrypt
        "$2y$12$MBH0rEzEXrAq8ukNA1LBKeYPWS2CcvoZeGwEtnuFNk4ONjN9LFpKK",  # generated from htpasswd -nbBC 12 "Test123"
        "$2y$12$gKLTXdWkOUFtvUOVh9aO2.S4V.YczMUQxq2foYadyMfpQomfKVnEa",  # generated from htpasswd -nbBC 12 "Test123"
        get_password_hash("Test123!"),  # generated from bcrypt
        get_password_hash("Test123!"),  # generated from bcrypt
    ],
)
def test_verify(password_hash):
    """
    Test the verify_password function across multiple bcrypt hash formats.

    This test verifies password validation for various bcrypt hash variants:
      - Standard bcrypt hashes (prefix $2b$)
      - Apache htpasswd generated hashes (prefix $2y$)

    All test cases use:
    - Password: "Test123!"
    - Cost factor: 12
    - Hash sources:
        - Python bcrypt library
        - Apache htpasswd utility (htpasswd -nbBC 12)

    Bcrypt’s design features memory-hard operations (using 4KB RAM for Blowfish’s S-boxes)
    and a strictly sequential key setup where each computation depends on the previous result.
    This creates a memory bottleneck that hinders parallel GPU/ASIC attacks, reducing hardware
    acceleration benefits compared to algorithms like MD5 or SHA256.

    Args:
      password_hash (str): Parameterized bcrypt hash.

    Raises:
      AssertionError: If password verification fails.
    """
    assert verify_password("Test123!", password_hash)
