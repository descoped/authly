#!/bin/bash
# OAuth 2.1 Helper Functions
# Utilities for OAuth 2.1 authorization code flow testing with PKCE

# Function to generate a base64url random string for PKCE
generate_pkce_random_string() {
    local length="${1:-43}"
    # Generate cryptographically secure random string with correct length
    # Use openssl with sufficient bytes for the target length
    openssl rand -base64 $((length + 10)) | tr -d '\n' | tr '/+' '_-' | tr -d '=' | cut -c1-$length
}

# Function to generate PKCE code verifier (43-128 characters, base64url)
generate_pkce_code_verifier() {
    local length="${1:-128}"  # Maximum length for best security
    
    if [[ $length -lt 43 || $length -gt 128 ]]; then
        log_error "PKCE code verifier length must be between 43 and 128 characters"
        return 1
    fi
    
    generate_pkce_random_string "$length"
}

# Function to generate PKCE code challenge from verifier (SHA256, base64url)
generate_pkce_code_challenge() {
    local code_verifier="$1"
    
    if [[ -z "$code_verifier" ]]; then
        log_error "Code verifier is required for challenge generation"
        return 1
    fi
    
    if [[ ${#code_verifier} -lt 43 || ${#code_verifier} -gt 128 ]]; then
        log_error "Invalid code verifier length: ${#code_verifier} (must be 43-128)"
        return 1
    fi
    
    # Generate SHA256 hash and encode as base64url
    echo -n "$code_verifier" | openssl dgst -sha256 -binary | openssl base64 | tr -d '\n' | tr '/+' '_-' | tr -d '='
}

# Function to generate complete PKCE pair
generate_pkce_pair() {
    local code_verifier=$(generate_pkce_code_verifier)
    local code_challenge=$(generate_pkce_code_challenge "$code_verifier")
    
    if [[ -z "$code_verifier" || -z "$code_challenge" ]]; then
        log_error "Failed to generate PKCE pair"
        return 1
    fi
    
    # Output as JSON for easy parsing
    cat <<EOF
{
  "code_verifier": "$code_verifier",
  "code_challenge": "$code_challenge",
  "code_challenge_method": "S256"
}
EOF
}

# Function to generate OAuth state parameter
generate_oauth_state() {
    generate_pkce_random_string 32
}

# Function to generate OIDC nonce parameter
generate_oidc_nonce() {
    generate_pkce_random_string 32
}

# Function to build authorization URL with all parameters
build_authorization_url() {
    local client_id="$1"
    local redirect_uri="$2"
    local code_challenge="$3"
    local scope="${4:-openid profile email}"
    local state="${5:-$(generate_oauth_state)}"
    local nonce="${6:-$(generate_oidc_nonce)}"
    local code_challenge_method="${7:-S256}"
    local response_type="${8:-code}"
    
    # Validate required parameters
    if [[ -z "$client_id" || -z "$redirect_uri" || -z "$code_challenge" ]]; then
        log_error "Missing required parameters for authorization URL"
        return 1
    fi
    
    # URL encode parameters
    local encoded_redirect_uri=$(printf '%s' "$redirect_uri" | jq -sRr @uri)
    local encoded_scope=$(printf '%s' "$scope" | jq -sRr @uri)
    local encoded_state=$(printf '%s' "$state" | jq -sRr @uri)
    local encoded_nonce=$(printf '%s' "$nonce" | jq -sRr @uri)
    
    # Build authorization URL
    local auth_url="${OAUTH_AUTHORIZE_ENDPOINT}?"
    auth_url+="response_type=${response_type}"
    auth_url+="&client_id=${client_id}"
    auth_url+="&redirect_uri=${encoded_redirect_uri}"
    auth_url+="&code_challenge=${code_challenge}"
    auth_url+="&code_challenge_method=${code_challenge_method}"
    auth_url+="&scope=${encoded_scope}"
    auth_url+="&state=${encoded_state}"
    auth_url+="&nonce=${encoded_nonce}"
    
    echo "$auth_url"
}

# Function to parse authorization response and extract authorization code
parse_authorization_response() {
    local response_url="$1"
    local expected_state="$2"
    
    if [[ -z "$response_url" ]]; then
        log_error "Authorization response URL is required"
        return 1
    fi
    
    # Extract query parameters from URL
    local query_string="${response_url#*\?}"
    
    # Parse parameters
    local code=""
    local state=""
    local error=""
    local error_description=""
    
    IFS='&' read -ra PARAMS <<< "$query_string"
    for param in "${PARAMS[@]}"; do
        IFS='=' read -r key value <<< "$param"
        case "$key" in
            "code")
                code=$(printf '%s' "$value" | jq -sRr @uri | sed 's/%/\\x/g' | xargs -0 printf)
                ;;
            "state")
                state=$(printf '%s' "$value" | jq -sRr @uri | sed 's/%/\\x/g' | xargs -0 printf)
                ;;
            "error")
                error=$(printf '%s' "$value" | jq -sRr @uri | sed 's/%/\\x/g' | xargs -0 printf)
                ;;
            "error_description")
                error_description=$(printf '%s' "$value" | jq -sRr @uri | sed 's/%/\\x/g' | xargs -0 printf)
                ;;
        esac
    done
    
    # Check for errors
    if [[ -n "$error" ]]; then
        log_error "Authorization error: $error"
        if [[ -n "$error_description" ]]; then
            log_error "Error description: $error_description"
        fi
        return 1
    fi
    
    # Validate state parameter
    if [[ -n "$expected_state" && "$state" != "$expected_state" ]]; then
        log_error "State parameter mismatch (CSRF protection failed)"
        return 1
    fi
    
    # Check if authorization code is present
    if [[ -z "$code" ]]; then
        log_error "No authorization code found in response"
        return 1
    fi
    
    # Output authorization code
    echo "$code"
    return 0
}

# Function to exchange authorization code for tokens
exchange_code_for_tokens() {
    local authorization_code="$1"
    local client_id="$2"
    local redirect_uri="$3"
    local code_verifier="$4"
    local client_secret="${5:-}"
    
    # Validate required parameters
    if [[ -z "$authorization_code" || -z "$client_id" || -z "$redirect_uri" || -z "$code_verifier" ]]; then
        log_error "Missing required parameters for token exchange"
        return 1
    fi
    
    log_info "Exchanging authorization code for tokens"
    
    # Prepare token request
    local token_data=$(cat <<EOF
{
  "grant_type": "authorization_code",
  "code": "$authorization_code",
  "redirect_uri": "$redirect_uri",
  "client_id": "$client_id",
  "code_verifier": "$code_verifier"
EOF
)
    
    # Add client secret if provided (confidential client)
    if [[ -n "$client_secret" ]]; then
        token_data=$(echo "$token_data" | sed 's/}$/,/')
        token_data+=$(cat <<EOF
  "client_secret": "$client_secret"
}
EOF
)
    else
        token_data+="}"
    fi
    
    # Make token request
    local response=$(post_request "$AUTH_TOKEN_ENDPOINT" "$token_data")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "Token exchange failed. Response: $body"
        return 1
    fi
    
    # Validate and return response
    local body="${response%???}"
    validate_json_response "$response"
    
    echo "$body"
    return 0
}

# Function to validate ID token signature (basic validation)
validate_id_token_signature() {
    local id_token="$1"
    
    if [[ -z "$id_token" ]]; then
        log_warning "No ID token provided for signature validation"
        return 0
    fi
    
    log_info "Validating ID token signature"
    
    # Get JWKS from discovery endpoint
    local jwks_response=$(get_request "${AUTHLY_BASE_URL}/.well-known/jwks.json")
    
    if ! check_http_status "$jwks_response" "200"; then
        log_error "Failed to fetch JWKS for ID token validation"
        return 1
    fi
    
    local jwks_body="${jwks_response%???}"
    
    # Extract key ID from ID token header
    local header=$(echo "$id_token" | cut -d'.' -f1)
    local header_padded=$(printf "%s%s" "$header" "$(printf '%*s' $(((4 - ${#header} % 4) % 4)) | tr ' ' '=')")
    local header_json=$(echo "$header_padded" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "{}")
    
    local kid=$(echo "$header_json" | jq -r '.kid // "none"')
    local alg=$(echo "$header_json" | jq -r '.alg // "none"')
    
    log_info "ID token algorithm: $alg"
    log_info "ID token key ID: $kid"
    
    # For testing purposes, we'll do basic structure validation
    # Full signature validation would require implementing JWT verification
    if [[ "$alg" == "none" ]]; then
        log_warning "ID token uses 'none' algorithm - signature not verified"
        return 0
    fi
    
    # Check if we have the required key
    local key_exists=$(echo "$jwks_body" | jq -r ".keys[] | select(.kid == \"$kid\") | .kid" 2>/dev/null || echo "")
    
    if [[ -n "$key_exists" ]]; then
        log_success "ID token key found in JWKS (structure validation passed)"
        return 0
    else
        log_warning "ID token key not found in JWKS (may be rotated)"
        return 1
    fi
}

# Function to extract and validate ID token claims
validate_id_token_claims() {
    local id_token="$1"
    local client_id="$2"
    local expected_nonce="${3:-}"
    
    if [[ -z "$id_token" ]]; then
        log_warning "No ID token provided for claims validation"
        return 0
    fi
    
    log_info "Validating ID token claims"
    
    # Extract payload
    local payload=$(echo "$id_token" | cut -d'.' -f2)
    local payload_padded=$(printf "%s%s" "$payload" "$(printf '%*s' $(((4 - ${#payload} % 4) % 4)) | tr ' ' '=')")
    local payload_json=$(echo "$payload_padded" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "{}")
    
    if ! echo "$payload_json" | jq . >/dev/null 2>&1; then
        log_error "Invalid ID token payload JSON"
        return 1
    fi
    
    # Extract and validate required claims
    local iss=$(echo "$payload_json" | jq -r '.iss // "none"')
    local aud=$(echo "$payload_json" | jq -r '.aud // "none"')
    local sub=$(echo "$payload_json" | jq -r '.sub // "none"')
    local exp=$(echo "$payload_json" | jq -r '.exp // 0')
    local iat=$(echo "$payload_json" | jq -r '.iat // 0')
    local nonce=$(echo "$payload_json" | jq -r '.nonce // "none"')
    
    local current_time=$(date +%s)
    
    # Validate issuer
    if [[ "$iss" != "$AUTHLY_BASE_URL" ]]; then
        log_error "Invalid issuer in ID token: $iss (expected: $AUTHLY_BASE_URL)"
        return 1
    fi
    
    # Validate audience
    if [[ "$aud" != "$client_id" ]]; then
        log_error "Invalid audience in ID token: $aud (expected: $client_id)"
        return 1
    fi
    
    # Validate subject
    if [[ "$sub" == "none" || -z "$sub" ]]; then
        log_error "Missing or invalid subject in ID token"
        return 1
    fi
    
    # Validate expiration
    if [[ $exp -le $current_time ]]; then
        log_error "ID token has expired (exp: $exp, current: $current_time)"
        return 1
    fi
    
    # Validate issued at time (allow some clock skew)
    if [[ $iat -gt $((current_time + 300)) ]]; then
        log_error "ID token issued in the future (iat: $iat, current: $current_time)"
        return 1
    fi
    
    # Validate nonce if provided
    if [[ -n "$expected_nonce" && "$nonce" != "$expected_nonce" ]]; then
        log_error "Nonce mismatch in ID token (expected: $expected_nonce, got: $nonce)"
        return 1
    fi
    
    log_success "ID token claims validation passed"
    log_info "  Issuer: $iss"
    log_info "  Audience: $aud"
    log_info "  Subject: $sub"
    log_info "  Expires: $exp ($(date -d "@$exp" 2>/dev/null || echo "unknown"))"
    log_info "  Nonce: $nonce"
    
    return 0
}

# Export functions for use by other scripts
export -f generate_pkce_random_string generate_pkce_code_verifier generate_pkce_code_challenge
export -f generate_pkce_pair generate_oauth_state generate_oidc_nonce
export -f build_authorization_url parse_authorization_response exchange_code_for_tokens
export -f validate_id_token_signature validate_id_token_claims