from datetime import UTC, datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class ClientType(str, Enum):
    """OAuth 2.1 client types"""

    CONFIDENTIAL = "confidential"  # Can securely store credentials
    PUBLIC = "public"  # Cannot securely store credentials (e.g., mobile/SPA)


class TokenEndpointAuthMethod(str, Enum):
    """OAuth 2.1 token endpoint authentication methods"""

    CLIENT_SECRET_BASIC = "client_secret_basic"  # HTTP Basic auth
    CLIENT_SECRET_POST = "client_secret_post"  # POST body
    NONE = "none"  # No authentication (public clients with PKCE)


class IDTokenSigningAlgorithm(str, Enum):
    """OpenID Connect ID token signing algorithms"""

    RS256 = "RS256"  # RSA using SHA-256 (default and recommended)
    HS256 = "HS256"  # HMAC using SHA-256
    ES256 = "ES256"  # ECDSA using P-256 and SHA-256


class SubjectType(str, Enum):
    """OpenID Connect subject identifier types"""

    PUBLIC = "public"  # Same sub value for all clients
    PAIRWISE = "pairwise"  # Different sub value per client


class GrantType(str, Enum):
    """OAuth 2.1 supported grant types"""

    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    # Note: OAuth 2.1 deprecates implicit and password grants


class ResponseType(str, Enum):
    """OAuth 2.1 supported response types"""

    CODE = "code"  # Authorization code flow


class CodeChallengeMethod(str, Enum):
    """PKCE code challenge methods - OAuth 2.1 only allows S256"""

    S256 = "S256"  # SHA256 hash (OAuth 2.1 requirement)


class ResponseMode(str, Enum):
    """OpenID Connect response modes"""

    QUERY = "query"
    FRAGMENT = "fragment"
    FORM_POST = "form_post"


class Display(str, Enum):
    """OpenID Connect display parameter values"""

    PAGE = "page"
    POPUP = "popup"
    TOUCH = "touch"
    WAP = "wap"


class Prompt(str, Enum):
    """OpenID Connect prompt parameter values"""

    NONE = "none"
    LOGIN = "login"
    CONSENT = "consent"
    SELECT_ACCOUNT = "select_account"


class OAuthClientModel(BaseModel):
    """Model representing an OAuth 2.1 client application"""

    id: UUID
    client_id: str = Field(..., min_length=1, max_length=255)
    client_secret_hash: str | None = Field(None, max_length=255)  # NULL for public clients
    client_name: str = Field(..., min_length=1, max_length=255)
    client_type: ClientType
    redirect_uris: list[str] = Field(..., min_items=1)  # At least one redirect URI required
    grant_types: list[GrantType] = Field(default=[GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN])
    response_types: list[ResponseType] = Field(default=[ResponseType.CODE])
    scope: str | None = None  # Default scopes (space-separated)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    is_active: bool = True

    # OAuth 2.1 specific fields
    require_pkce: bool = True  # OAuth 2.1 recommends PKCE for all clients
    token_endpoint_auth_method: TokenEndpointAuthMethod = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC

    # Additional metadata
    client_uri: str | None = None  # Homepage of the client
    logo_uri: str | None = None  # Logo for consent screen
    tos_uri: str | None = None  # Terms of service
    policy_uri: str | None = None  # Privacy policy
    jwks_uri: str | None = None  # JSON Web Key Set URI
    software_id: str | None = Field(None, max_length=255)
    software_version: str | None = Field(None, max_length=50)

    # OpenID Connect specific fields
    id_token_signed_response_alg: IDTokenSigningAlgorithm = IDTokenSigningAlgorithm.RS256
    subject_type: SubjectType = SubjectType.PUBLIC
    sector_identifier_uri: str | None = None  # For pairwise subject types
    require_auth_time: bool = False  # Whether auth_time claim is required in ID tokens
    default_max_age: int | None = None  # Default max_age for authentication
    initiate_login_uri: str | None = None  # URI for third-party initiated login
    request_uris: list[str] = Field(default_factory=list)  # Pre-registered request URIs

    # OIDC Client Registration fields
    application_type: str = "web"  # "web" or "native"
    contacts: list[str] = Field(default_factory=list)  # Contact email addresses
    client_name_localized: dict | None = None  # Localized client names
    logo_uri_localized: dict | None = None  # Localized logo URIs
    client_uri_localized: dict | None = None  # Localized client URIs
    policy_uri_localized: dict | None = None  # Localized policy URIs
    tos_uri_localized: dict | None = None  # Localized ToS URIs

    def is_public_client(self) -> bool:
        """Check if this is a public client (no secret required)"""
        return self.client_type == ClientType.PUBLIC

    def is_confidential_client(self) -> bool:
        """Check if this is a confidential client (secret required)"""
        return self.client_type == ClientType.CONFIDENTIAL

    def supports_grant_type(self, grant_type: GrantType) -> bool:
        """Check if client supports a specific grant type"""
        return grant_type in self.grant_types

    def supports_response_type(self, response_type: ResponseType) -> bool:
        """Check if client supports a specific response type"""
        return response_type in self.response_types

    def is_redirect_uri_allowed(self, redirect_uri: str) -> bool:
        """Check if a redirect URI is allowed for this client"""
        return redirect_uri in self.redirect_uris

    def is_oidc_client(self) -> bool:
        """Check if this client has OpenID Connect capabilities (openid scope in default scopes)"""
        if not self.scope:
            return False
        scopes = self.scope.split()
        return "openid" in scopes

    def get_oidc_scopes(self) -> list[str]:
        """Get OIDC-specific scopes for this client"""
        if not self.scope:
            return []
        scopes = self.scope.split()
        oidc_scopes = ["openid", "profile", "email", "address", "phone"]
        return [scope for scope in scopes if scope in oidc_scopes]


class OAuthScopeModel(BaseModel):
    """Model representing an OAuth 2.1 scope"""

    id: UUID
    scope_name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    is_default: bool = False  # Whether this scope is granted by default
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    is_active: bool = True


class OAuthClientScopeModel(BaseModel):
    """Model representing client-scope associations"""

    id: UUID
    client_id: UUID
    scope_id: UUID
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class OAuthAuthorizationCodeModel(BaseModel):
    """Model representing OAuth 2.1 authorization codes with PKCE and OpenID Connect support"""

    id: UUID
    code: str = Field(..., min_length=1, max_length=255)
    client_id: UUID
    user_id: UUID
    redirect_uri: str = Field(..., min_length=1)
    scope: str | None = None  # Granted scopes (space-separated)
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    used_at: datetime | None = None
    is_used: bool = False

    # PKCE fields (OAuth 2.1 requirement)
    code_challenge: str = Field(..., min_length=1, max_length=255)
    code_challenge_method: CodeChallengeMethod = CodeChallengeMethod.S256

    # OpenID Connect parameters
    nonce: str | None = Field(None, max_length=255)  # OpenID Connect nonce
    state: str | None = Field(None, max_length=255)  # CSRF protection
    response_mode: ResponseMode | None = Field(None)  # Response mode
    display: Display | None = Field(None)  # Display preference
    prompt: Prompt | None = Field(None)  # Prompt parameter
    max_age: int | None = Field(None)  # Maximum authentication age
    ui_locales: str | None = Field(None, max_length=255)  # UI locales
    id_token_hint: str | None = Field(None, max_length=2048)  # ID token hint
    login_hint: str | None = Field(None, max_length=255)  # Login hint
    acr_values: str | None = Field(None, max_length=255)  # ACR values

    def is_expired(self) -> bool:
        """Check if the authorization code has expired"""
        return datetime.now(UTC) > self.expires_at

    def is_valid(self) -> bool:
        """Check if the authorization code is valid (not used and not expired)"""
        return not self.is_used and not self.is_expired()

    def is_oidc_request(self) -> bool:
        """Check if this authorization code is for an OpenID Connect request"""
        if not self.scope:
            return False
        return "openid" in self.scope.split()


class OAuthTokenScopeModel(BaseModel):
    """Model representing token-scope associations"""

    id: UUID
    token_id: UUID
    scope_id: UUID
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# Request/Response models for API endpoints


class OAuthClientCreateRequest(BaseModel):
    """Request model for creating OAuth clients"""

    client_name: str = Field(..., min_length=1, max_length=255)
    client_type: ClientType
    redirect_uris: list[str] = Field(..., min_items=1)
    scope: str | None = None
    grant_types: list[GrantType] | None = None
    response_types: list[ResponseType] | None = None
    require_pkce: bool = True
    token_endpoint_auth_method: TokenEndpointAuthMethod | None = None

    # Metadata
    client_uri: str | None = None
    logo_uri: str | None = None
    tos_uri: str | None = None
    policy_uri: str | None = None
    software_id: str | None = None
    software_version: str | None = None

    # OpenID Connect specific fields
    id_token_signed_response_alg: IDTokenSigningAlgorithm | None = None
    subject_type: SubjectType | None = None
    sector_identifier_uri: str | None = None
    require_auth_time: bool = False
    default_max_age: int | None = None
    initiate_login_uri: str | None = None
    request_uris: list[str] | None = None
    application_type: str | None = None
    contacts: list[str] | None = None


class OAuthClientResponse(BaseModel):
    """Response model for OAuth client information"""

    id: UUID
    client_id: str
    client_name: str
    client_type: ClientType
    redirect_uris: list[str]
    grant_types: list[GrantType]
    response_types: list[ResponseType]
    scope: str | None
    created_at: datetime
    updated_at: datetime
    is_active: bool
    require_pkce: bool
    token_endpoint_auth_method: TokenEndpointAuthMethod

    # Metadata (excluding sensitive info like client_secret_hash)
    client_uri: str | None
    logo_uri: str | None
    tos_uri: str | None
    policy_uri: str | None
    software_id: str | None
    software_version: str | None

    # OpenID Connect specific fields
    id_token_signed_response_alg: IDTokenSigningAlgorithm = IDTokenSigningAlgorithm.RS256
    subject_type: SubjectType = SubjectType.PUBLIC
    sector_identifier_uri: str | None = None
    require_auth_time: bool = False
    default_max_age: int | None = None
    initiate_login_uri: str | None = None
    request_uris: list[str] = Field(default_factory=list)
    application_type: str = "web"
    contacts: list[str] = Field(default_factory=list)


class OAuthClientCredentialsResponse(BaseModel):
    """Response model for OAuth client credentials (only returned once)"""

    client_id: str
    client_secret: str | None = None  # Only for confidential clients
    client_type: ClientType
    client_name: str  # Added for test compatibility


# Authorization Flow Request/Response Models


class OAuthAuthorizationRequest(BaseModel):
    """OAuth 2.1 Authorization Request Model (RFC 6749 Section 4.1.1 + PKCE) with OpenID Connect extensions"""

    # Required OAuth 2.1 parameters
    response_type: ResponseType = Field(..., description="Must be 'code' for authorization code flow")
    client_id: str = Field(..., min_length=1, max_length=255, description="Client identifier")
    redirect_uri: str = Field(..., min_length=1, description="Client redirect URI")

    # PKCE parameters (OAuth 2.1 mandatory)
    code_challenge: str = Field(..., min_length=43, max_length=128, description="PKCE code challenge")
    code_challenge_method: CodeChallengeMethod = Field(
        default=CodeChallengeMethod.S256, description="PKCE challenge method"
    )

    # Optional parameters
    scope: str | None = Field(None, description="Requested scopes (space-separated)")
    state: str | None = Field(None, max_length=255, description="CSRF protection parameter")

    # OpenID Connect specific parameters
    nonce: str | None = Field(None, max_length=255, description="OpenID Connect nonce for ID token binding")
    response_mode: ResponseMode | None = Field(None, description="How the authorization response should be returned")
    display: Display | None = Field(None, description="How the authorization server displays authentication interface")
    prompt: Prompt | None = Field(None, description="Whether to prompt for re-authentication/consent")
    max_age: int | None = Field(None, ge=0, description="Maximum authentication age in seconds")
    ui_locales: str | None = Field(None, max_length=255, description="Preferred UI languages (space-separated)")
    id_token_hint: str | None = Field(
        None, max_length=2048, description="ID token hint for logout or re-authentication"
    )
    login_hint: str | None = Field(None, max_length=255, description="Hint to identify the user for authentication")
    acr_values: str | None = Field(None, max_length=255, description="Authentication Context Class Reference values")

    def get_scope_list(self) -> list[str]:
        """Convert space-separated scopes to list"""
        if not self.scope:
            return []
        return self.scope.split()

    def get_ui_locales_list(self) -> list[str]:
        """Convert space-separated UI locales to list"""
        if not self.ui_locales:
            return []
        return self.ui_locales.split()

    def get_acr_values_list(self) -> list[str]:
        """Convert space-separated ACR values to list"""
        if not self.acr_values:
            return []
        return self.acr_values.split()

    def is_oidc_request(self) -> bool:
        """Check if this is an OpenID Connect request (contains 'openid' scope)"""
        return "openid" in self.get_scope_list()

    def validate_pkce_params(self) -> bool:
        """Validate PKCE parameters according to OAuth 2.1"""
        # Code challenge must be base64url-encoded with length 43-128
        if not self.code_challenge or len(self.code_challenge) < 43 or len(self.code_challenge) > 128:
            return False

        # OAuth 2.1 only allows S256
        return self.code_challenge_method == CodeChallengeMethod.S256

    def validate_oidc_params(self) -> bool:
        """Validate OpenID Connect specific parameters"""
        # If prompt=none, user must not be prompted for authentication or consent
        if self.prompt == Prompt.NONE:
            # Additional validation could be added here
            return True

        # max_age must be non-negative if provided
        return not (self.max_age is not None and self.max_age < 0)


class OAuthAuthorizationResponse(BaseModel):
    """OAuth 2.1 Authorization Response Model (RFC 6749 Section 4.1.2)"""

    # Success response
    code: str | None = Field(None, description="Authorization code")
    state: str | None = Field(None, description="State parameter from request")

    # Error response (RFC 6749 Section 4.1.2.1)
    error: str | None = Field(None, description="Error code")
    error_description: str | None = Field(None, description="Human-readable error description")
    error_uri: str | None = Field(None, description="URI to error information page")

    def is_success(self) -> bool:
        """Check if this is a successful response"""
        return self.code is not None and self.error is None

    def is_error(self) -> bool:
        """Check if this is an error response"""
        return self.error is not None


class OAuthAuthorizationErrorResponse(BaseModel):
    """OAuth 2.1 Authorization Error Response Model"""

    error: str = Field(..., description="Error code")
    error_description: str | None = Field(None, description="Human-readable error description")
    error_uri: str | None = Field(None, description="URI to error information page")
    state: str | None = Field(None, description="State parameter from request")


# OAuth 2.1 Error Codes (RFC 6749 Section 4.1.2.1)
class AuthorizationError(str, Enum):
    """OAuth 2.1 Authorization Error Codes"""

    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    ACCESS_DENIED = "access_denied"
    UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
    INVALID_SCOPE = "invalid_scope"
    SERVER_ERROR = "server_error"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"


# User Consent Models


class UserConsentRequest(BaseModel):
    """User consent request for authorization flow with OpenID Connect support"""

    client_id: str = Field(..., description="Client requesting authorization")
    redirect_uri: str = Field(..., description="Redirect URI")
    scope: str | None = Field(None, description="Requested scopes")
    state: str | None = Field(None, description="State parameter")
    code_challenge: str = Field(..., description="PKCE code challenge")
    code_challenge_method: CodeChallengeMethod = Field(default=CodeChallengeMethod.S256)

    # OpenID Connect parameters
    nonce: str | None = Field(None, description="OpenID Connect nonce")
    response_mode: ResponseMode | None = Field(None, description="Response mode")
    display: Display | None = Field(None, description="Display preference")
    prompt: Prompt | None = Field(None, description="Prompt parameter")
    max_age: int | None = Field(None, description="Maximum authentication age")
    ui_locales: str | None = Field(None, description="UI locales preference")
    id_token_hint: str | None = Field(None, description="ID token hint")
    login_hint: str | None = Field(None, description="Login hint")
    acr_values: str | None = Field(None, description="ACR values")

    # User decision
    user_id: UUID = Field(..., description="Authenticated user ID")
    approved: bool = Field(..., description="Whether user approved the request")
    approved_scopes: list[str] | None = Field(None, description="Scopes approved by user")


class AuthorizationCodeGrantRequest(BaseModel):
    """Authorization code grant request for token endpoint"""

    grant_type: GrantType = Field(..., description="Must be 'authorization_code'")
    code: str = Field(..., description="Authorization code received")
    redirect_uri: str = Field(..., description="Redirect URI from authorization request")
    client_id: str = Field(..., description="Client identifier")

    # PKCE verification (OAuth 2.1 mandatory)
    code_verifier: str = Field(..., min_length=43, max_length=128, description="PKCE code verifier")

    def validate_pkce_verifier(self) -> bool:
        """Validate PKCE code verifier according to OAuth 2.1"""
        # Code verifier must be base64url-encoded with length 43-128
        return 43 <= len(self.code_verifier) <= 128
