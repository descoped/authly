#!/usr/bin/env python3
"""
Simple OIDC Conformance Test
Tests basic OIDC flows against Authly
"""

import json
import requests
import sys
from datetime import datetime

# Disable SSL warnings for self-signed certificates
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def test_oidc_discovery():
    """Test OIDC discovery endpoints"""
    print("\n🔍 Testing OIDC Discovery...")

    # Test with underscore (current implementation)
    try:
        response = requests.get("http://localhost:8000/.well-known/openid_configuration")
        if response.status_code == 200:
            print("  ⚠️  Works with underscore but VIOLATES SPEC")
            config = response.json()
            print(f"  ✓ Issuer: {config.get('issuer')}")
            print(f"  ✓ Authorization endpoint: {config.get('authorization_endpoint')}")
            print(f"  ✓ Token endpoint: {config.get('token_endpoint')}")
        else:
            print(f"  ✗ Underscore endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"  ✗ Error: {e}")

    # Test with hyphen (spec-compliant)
    try:
        response = requests.get("http://localhost:8000/.well-known/openid-configuration")
        if response.status_code == 200:
            print("  ✅ Works with hyphen (SPEC COMPLIANT)")
        else:
            print(f"  ❌ SPEC VIOLATION: Hyphen endpoint returns {response.status_code}")
    except Exception as e:
        print(f"  ✗ Error: {e}")


def test_jwks():
    """Test JWKS endpoint"""
    print("\n🔑 Testing JWKS Endpoint...")
    try:
        response = requests.get("http://localhost:8000/.well-known/jwks.json")
        if response.status_code == 200:
            jwks = response.json()
            print(f"  ✓ JWKS available with {len(jwks.get('keys', []))} key(s)")
        else:
            print(f"  ✗ JWKS failed: {response.status_code}")
    except Exception as e:
        print(f"  ✗ Error: {e}")


def test_authorization_endpoint():
    """Test authorization endpoint"""
    print("\n🔐 Testing Authorization Endpoint...")
    params = {
        "client_id": "test-client",
        "response_type": "code",
        "redirect_uri": "http://localhost:8080/callback",
        "scope": "openid",
        "state": "test123",
    }

    try:
        response = requests.get("http://localhost:8000/api/v1/oauth/authorize", params=params)
        # We expect either a redirect or an error
        if response.status_code in [401, 403]:
            print(f"  ⚠️  Returns {response.status_code} instead of redirect")
        elif response.status_code == 302:
            print("  ✓ Returns redirect as expected")
        else:
            print(f"  ? Unexpected status: {response.status_code}")
    except Exception as e:
        print(f"  ✗ Error: {e}")


def test_token_endpoint():
    """Test token endpoint error handling"""
    print("\n🎫 Testing Token Endpoint...")

    # Test missing parameters
    try:
        response = requests.post("http://localhost:8000/api/v1/oauth/token", data={})
        if response.status_code == 422:
            print("  ⚠️  Returns 422 for invalid request (should be 400)")
        elif response.status_code == 400:
            print("  ✓ Returns 400 for invalid request")
        else:
            print(f"  ? Unexpected status: {response.status_code}")
    except Exception as e:
        print(f"  ✗ Error: {e}")

    # Test with invalid grant
    data = {"grant_type": "authorization_code", "code": "invalid", "client_id": "test", "client_secret": "test"}
    try:
        response = requests.post("http://localhost:8000/api/v1/oauth/token", data=data)
        print(f"  → Invalid grant returns: {response.status_code}")
        if response.status_code == 400:
            error = response.json()
            print(f"    Error: {error.get('error', 'unknown')}")
    except Exception as e:
        print(f"  ✗ Error: {e}")


def test_userinfo_endpoint():
    """Test userinfo endpoint"""
    print("\n👤 Testing UserInfo Endpoint...")

    try:
        response = requests.get("http://localhost:8000/oidc/userinfo")
        if response.status_code == 401:
            print("  ✓ Returns 401 without authentication")
        else:
            print(f"  ? Unexpected status: {response.status_code}")
    except Exception as e:
        print(f"  ✗ Error: {e}")


def main():
    print("=" * 50)
    print("OIDC Conformance Quick Test")
    print("=" * 50)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Run tests
    test_oidc_discovery()
    test_jwks()
    test_authorization_endpoint()
    test_token_endpoint()
    test_userinfo_endpoint()

    print("\n" + "=" * 50)
    print("⚠️  Key Issues Found:")
    print("  1. Discovery endpoint uses underscore (spec violation)")
    print("  2. Token endpoint returns 422 instead of 400")
    print("  3. Authorization endpoint returns 401 instead of redirect")
    print("\n💡 Fix these issues to improve OIDC compliance")
    print("=" * 50)


if __name__ == "__main__":
    main()
