from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
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
    client_secret_hash: Optional[str] = Field(None, max_length=255)  # NULL for public clients
    client_name: str = Field(..., min_length=1, max_length=255)
    client_type: ClientType
    redirect_uris: List[str] = Field(..., min_items=1)  # At least one redirect URI required
    grant_types: List[GrantType] = Field(default=[GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN])
    response_types: List[ResponseType] = Field(default=[ResponseType.CODE])
    scope: Optional[str] = None  # Default scopes (space-separated)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True

    # OAuth 2.1 specific fields
    require_pkce: bool = True  # OAuth 2.1 recommends PKCE for all clients
    token_endpoint_auth_method: TokenEndpointAuthMethod = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC

    # Additional metadata
    client_uri: Optional[str] = None  # Homepage of the client
    logo_uri: Optional[str] = None  # Logo for consent screen
    tos_uri: Optional[str] = None  # Terms of service
    policy_uri: Optional[str] = None  # Privacy policy
    jwks_uri: Optional[str] = None  # JSON Web Key Set URI
    software_id: Optional[str] = Field(None, max_length=255)
    software_version: Optional[str] = Field(None, max_length=50)

    # OpenID Connect specific fields
    id_token_signed_response_alg: IDTokenSigningAlgorithm = IDTokenSigningAlgorithm.RS256
    subject_type: SubjectType = SubjectType.PUBLIC
    sector_identifier_uri: Optional[str] = None  # For pairwise subject types
    require_auth_time: bool = False  # Whether auth_time claim is required in ID tokens
    default_max_age: Optional[int] = None  # Default max_age for authentication
    initiate_login_uri: Optional[str] = None  # URI for third-party initiated login
    request_uris: List[str] = Field(default_factory=list)  # Pre-registered request URIs

    # OIDC Client Registration fields
    application_type: str = "web"  # "web" or "native"
    contacts: List[str] = Field(default_factory=list)  # Contact email addresses
    client_name_localized: Optional[dict] = None  # Localized client names
    logo_uri_localized: Optional[dict] = None  # Localized logo URIs
    client_uri_localized: Optional[dict] = None  # Localized client URIs
    policy_uri_localized: Optional[dict] = None  # Localized policy URIs
    tos_uri_localized: Optional[dict] = None  # Localized ToS URIs

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

    def get_oidc_scopes(self) -> List[str]:
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
    description: Optional[str] = None
    is_default: bool = False  # Whether this scope is granted by default
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True


class OAuthClientScopeModel(BaseModel):
    """Model representing client-scope associations"""

    id: UUID
    client_id: UUID
    scope_id: UUID
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class OAuthAuthorizationCodeModel(BaseModel):
    """Model representing OAuth 2.1 authorization codes with PKCE and OpenID Connect support"""

    id: UUID
    code: str = Field(..., min_length=1, max_length=255)
    client_id: UUID
    user_id: UUID
    redirect_uri: str = Field(..., min_length=1)
    scope: Optional[str] = None  # Granted scopes (space-separated)
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    used_at: Optional[datetime] = None
    is_used: bool = False

    # PKCE fields (OAuth 2.1 requirement)
    code_challenge: str = Field(..., min_length=1, max_length=255)
    code_challenge_method: CodeChallengeMethod = CodeChallengeMethod.S256

    # OpenID Connect parameters
    nonce: Optional[str] = Field(None, max_length=255)  # OpenID Connect nonce
    state: Optional[str] = Field(None, max_length=255)  # CSRF protection
    response_mode: Optional[ResponseMode] = Field(None)  # Response mode
    display: Optional[Display] = Field(None)  # Display preference
    prompt: Optional[Prompt] = Field(None)  # Prompt parameter
    max_age: Optional[int] = Field(None)  # Maximum authentication age
    ui_locales: Optional[str] = Field(None, max_length=255)  # UI locales
    id_token_hint: Optional[str] = Field(None, max_length=2048)  # ID token hint
    login_hint: Optional[str] = Field(None, max_length=255)  # Login hint
    acr_values: Optional[str] = Field(None, max_length=255)  # ACR values

    def is_expired(self) -> bool:
        """Check if the authorization code has expired"""
        return datetime.now(timezone.utc) > self.expires_at

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
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# Request/Response models for API endpoints


class OAuthClientCreateRequest(BaseModel):
    """Request model for creating OAuth clients"""

    client_name: str = Field(..., min_length=1, max_length=255)
    client_type: ClientType
    redirect_uris: List[str] = Field(..., min_items=1)
    scope: Optional[str] = None
    grant_types: Optional[List[GrantType]] = None
    response_types: Optional[List[ResponseType]] = None
    require_pkce: bool = True
    token_endpoint_auth_method: Optional[TokenEndpointAuthMethod] = None

    # Metadata
    client_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    tos_uri: Optional[str] = None
    policy_uri: Optional[str] = None
    software_id: Optional[str] = None
    software_version: Optional[str] = None

    # OpenID Connect specific fields
    id_token_signed_response_alg: Optional[IDTokenSigningAlgorithm] = None
    subject_type: Optional[SubjectType] = None
    sector_identifier_uri: Optional[str] = None
    require_auth_time: bool = False
    default_max_age: Optional[int] = None
    initiate_login_uri: Optional[str] = None
    request_uris: Optional[List[str]] = None
    application_type: Optional[str] = None
    contacts: Optional[List[str]] = None


class OAuthClientResponse(BaseModel):
    """Response model for OAuth client information"""

    id: UUID
    client_id: str
    client_name: str
    client_type: ClientType
    redirect_uris: List[str]
    grant_types: List[GrantType]
    response_types: List[ResponseType]
    scope: Optional[str]
    created_at: datetime
    updated_at: datetime
    is_active: bool
    require_pkce: bool
    token_endpoint_auth_method: TokenEndpointAuthMethod

    # Metadata (excluding sensitive info like client_secret_hash)
    client_uri: Optional[str]
    logo_uri: Optional[str]
    tos_uri: Optional[str]
    policy_uri: Optional[str]
    software_id: Optional[str]
    software_version: Optional[str]

    # OpenID Connect specific fields
    id_token_signed_response_alg: IDTokenSigningAlgorithm = IDTokenSigningAlgorithm.RS256
    subject_type: SubjectType = SubjectType.PUBLIC
    sector_identifier_uri: Optional[str] = None
    require_auth_time: bool = False
    default_max_age: Optional[int] = None
    initiate_login_uri: Optional[str] = None
    request_uris: List[str] = Field(default_factory=list)
    application_type: str = "web"
    contacts: List[str] = Field(default_factory=list)


class OAuthClientCredentialsResponse(BaseModel):
    """Response model for OAuth client credentials (only returned once)"""

    client_id: str
    client_secret: Optional[str] = None  # Only for confidential clients
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
    scope: Optional[str] = Field(None, description="Requested scopes (space-separated)")
    state: Optional[str] = Field(None, max_length=255, description="CSRF protection parameter")

    # OpenID Connect specific parameters
    nonce: Optional[str] = Field(None, max_length=255, description="OpenID Connect nonce for ID token binding")
    response_mode: Optional[ResponseMode] = Field(None, description="How the authorization response should be returned")
    display: Optional[Display] = Field(
        None, description="How the authorization server displays authentication interface"
    )
    prompt: Optional[Prompt] = Field(None, description="Whether to prompt for re-authentication/consent")
    max_age: Optional[int] = Field(None, ge=0, description="Maximum authentication age in seconds")
    ui_locales: Optional[str] = Field(None, max_length=255, description="Preferred UI languages (space-separated)")
    id_token_hint: Optional[str] = Field(
        None, max_length=2048, description="ID token hint for logout or re-authentication"
    )
    login_hint: Optional[str] = Field(None, max_length=255, description="Hint to identify the user for authentication")
    acr_values: Optional[str] = Field(None, max_length=255, description="Authentication Context Class Reference values")

    def get_scope_list(self) -> List[str]:
        """Convert space-separated scopes to list"""
        if not self.scope:
            return []
        return self.scope.split()

    def get_ui_locales_list(self) -> List[str]:
        """Convert space-separated UI locales to list"""
        if not self.ui_locales:
            return []
        return self.ui_locales.split()

    def get_acr_values_list(self) -> List[str]:
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
        if self.max_age is not None and self.max_age < 0:
            return False

        return True


class OAuthAuthorizationResponse(BaseModel):
    """OAuth 2.1 Authorization Response Model (RFC 6749 Section 4.1.2)"""

    # Success response
    code: Optional[str] = Field(None, description="Authorization code")
    state: Optional[str] = Field(None, description="State parameter from request")

    # Error response (RFC 6749 Section 4.1.2.1)
    error: Optional[str] = Field(None, description="Error code")
    error_description: Optional[str] = Field(None, description="Human-readable error description")
    error_uri: Optional[str] = Field(None, description="URI to error information page")

    def is_success(self) -> bool:
        """Check if this is a successful response"""
        return self.code is not None and self.error is None

    def is_error(self) -> bool:
        """Check if this is an error response"""
        return self.error is not None


class OAuthAuthorizationErrorResponse(BaseModel):
    """OAuth 2.1 Authorization Error Response Model"""

    error: str = Field(..., description="Error code")
    error_description: Optional[str] = Field(None, description="Human-readable error description")
    error_uri: Optional[str] = Field(None, description="URI to error information page")
    state: Optional[str] = Field(None, description="State parameter from request")


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
    scope: Optional[str] = Field(None, description="Requested scopes")
    state: Optional[str] = Field(None, description="State parameter")
    code_challenge: str = Field(..., description="PKCE code challenge")
    code_challenge_method: CodeChallengeMethod = Field(default=CodeChallengeMethod.S256)

    # OpenID Connect parameters
    nonce: Optional[str] = Field(None, description="OpenID Connect nonce")
    response_mode: Optional[ResponseMode] = Field(None, description="Response mode")
    display: Optional[Display] = Field(None, description="Display preference")
    prompt: Optional[Prompt] = Field(None, description="Prompt parameter")
    max_age: Optional[int] = Field(None, description="Maximum authentication age")
    ui_locales: Optional[str] = Field(None, description="UI locales preference")
    id_token_hint: Optional[str] = Field(None, description="ID token hint")
    login_hint: Optional[str] = Field(None, description="Login hint")
    acr_values: Optional[str] = Field(None, description="ACR values")

    # User decision
    user_id: UUID = Field(..., description="Authenticated user ID")
    approved: bool = Field(..., description="Whether user approved the request")
    approved_scopes: Optional[List[str]] = Field(None, description="Scopes approved by user")


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
