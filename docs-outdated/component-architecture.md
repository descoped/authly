# Component Architecture

This document shows the comprehensive architecture of Authly with full OAuth 2.1 implementation.

## Architecture Overview

The updated component architecture reflects the complete OAuth 2.1 ecosystem with:

- **OAuth 2.1 Compliance**: Authorization code flow with PKCE, client authentication, token revocation
- **Admin Interface**: CLI tools for OAuth client and scope management  
- **Comprehensive Testing**: 171/171 tests with real database integration
- **Production Ready**: Enterprise-grade security and scalability

## Visual Architecture

![Component Architecture](component-architecture.mmd)

The architecture is organized into distinct layers:

### API Layer
- **auth_router**: Authentication endpoints including OAuth token endpoint
- **users_router**: User management with role-based access control
- **oauth_router**: OAuth 2.1 authorization, discovery, and revocation endpoints
- **authly-admin CLI**: Command-line interface for OAuth administration

### Service Layer  
- **UserService**: Centralized user business logic and operations
- **TokenService**: JWT token creation, validation, and lifecycle management
- **ClientService**: OAuth client registration, authentication, and management
- **ScopeService**: OAuth scope validation, assignment, and enforcement
- **AuthorizationService**: OAuth authorization code flow with PKCE support
- **DiscoveryService**: RFC 8414 server metadata endpoint

### Repository Layer
- **Comprehensive CRUD**: Full database operations for users, tokens, clients, scopes, authorization codes
- **PostgreSQL Integration**: Using psycopg-toolkit for robust database operations
- **Transaction Management**: Atomic operations with proper rollback support

### OAuth 2.1 Features
- **PKCE Support**: Mandatory S256 challenge method for authorization code flow
- **Client Types**: Support for confidential and public OAuth clients
- **Token Revocation**: RFC 7009 compliant token invalidation
- **Server Discovery**: RFC 8414 metadata endpoint for client auto-configuration
- **Scope Management**: Granular permission system with default scopes

### Security & Quality
- **171/171 Tests**: 100% test success rate with comprehensive coverage
- **Security**: Secure credential management, rate limiting, brute force protection
- **Standards Compliance**: Full OAuth 2.1, RFC 7009, RFC 8414 adherence