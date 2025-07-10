# User Account State Diagram

This document describes the user account lifecycle in Authly, including account states, transitions, and the relationship with OAuth 2.1 authentication and authorization.

## Overview

User accounts in Authly progress through various states from creation to deletion, with different capabilities and restrictions at each stage. The system supports role-based access control and account security measures.

## Visual Account States

![User Account State](user-account-state.mmd)

## Account States

### 1. Created
**Initial registration state after account creation**

**Characteristics:**
- Account exists in database with basic information
- Password has been securely hashed and stored
- No authentication capabilities yet
- Awaiting verification process

**Capabilities:**
- None - account cannot be used for authentication
- Visible to administrators for management

### 2. Unverified
**Default state for new accounts**

**Characteristics:**
- Account has basic information but lacks verification
- Cannot authenticate or access protected resources
- May have limited functionality for verification process

**Capabilities:**
- No login access
- May receive verification communications
- Can be verified by administrators

**Transitions:**
- **To Verified**: Admin verification or automated verification process
- **To Deleted**: Account cleanup or admin action

### 3. Verified
**Account has been verified but not yet used**

**Characteristics:**
- Account identity has been confirmed
- Ready for first authentication
- Full account capabilities pending first login

**Capabilities:**
- Can authenticate and receive tokens
- Access to user-level features
- Can be promoted to active on first login

**Transitions:**
- **To Active**: Successful first authentication
- **To Inactive**: Administrative deactivation

### 4. Active
**Fully functional user account**

**Characteristics:**
- Complete access to system features
- Can authenticate and receive tokens
- Participates in OAuth 2.1 flows as resource owner
- Standard user permissions and capabilities

**Capabilities:**
- Full authentication access
- Token generation and management
- OAuth client authorization and consent
- Profile management and updates
- Standard API access

**Transitions:**
- **To Admin**: Administrative promotion
- **To Inactive**: Administrative deactivation
- **To Locked**: Security lockout due to failed attempts
- **To Deleted**: Account deletion

### 5. Admin
**Enhanced privileges for system administration**

**Characteristics:**
- All capabilities of Active users
- Additional administrative permissions
- Can manage other users and system configuration
- Can access OAuth client and scope management

**Capabilities:**
- User account management (create, verify, deactivate)
- OAuth client registration and management
- Scope definition and assignment
- System configuration access
- Administrative API endpoints
- CLI admin tool access

**Transitions:**
- **To Active**: Administrative demotion
- **To Locked**: Security lockout (rare for admins)
- **To Deleted**: Account deletion

### 6. Locked
**Temporary security lockout state**

**Characteristics:**
- Account temporarily inaccessible due to security measures
- Usually triggered by multiple failed login attempts
- Automatic or manual unlock procedures available
- All existing tokens remain valid until expiration

**Capabilities:**
- No new authentication allowed
- Existing valid tokens continue to work
- Account information remains accessible to admins
- Security notifications may be sent

**Transitions:**
- **To Active**: Automatic unlock after timeout or manual admin unlock
- **To Inactive**: Administrative decision during lockout investigation

### 7. Inactive
**Administratively disabled account**

**Characteristics:**
- Account disabled by administrative action
- All authentication blocked
- Existing tokens may be revoked
- Account data preserved for potential reactivation

**Capabilities:**
- No authentication access
- All tokens invalidated on deactivation
- Account visible to administrators
- Can be reactivated by administrators

**Transitions:**
- **To Active**: Administrative reactivation
- **To Deleted**: Permanent account removal

## OAuth 2.1 Integration

### Account States and OAuth

**Active and Admin Users:**
- Can authorize OAuth applications
- Can grant scopes to third-party clients
- Can manage their OAuth consent decisions
- Tokens generated are tied to account state

**Verified Users:**
- Can participate in OAuth flows
- Limited to basic scope grants
- Full OAuth capabilities on promotion to Active

**Inactive/Locked Users:**
- Cannot authorize new OAuth applications
- Existing OAuth tokens may be revoked
- No new OAuth tokens generated

### Administrative Capabilities

**Admin Users Can:**
- Register and manage OAuth clients
- Define and configure authorization scopes
- Monitor OAuth usage and statistics
- Revoke OAuth tokens and authorizations
- Access CLI admin tools for OAuth management

### Token Lifecycle Integration

**Account State Changes Affect Tokens:**
- **Deactivation**: All user tokens invalidated
- **Lock**: New token generation blocked
- **Unlock**: Token generation resumed
- **Deletion**: All tokens permanently revoked

## Security Considerations

### Account Protection
- **Rate Limiting**: Failed login attempts trigger temporary locks
- **Token Revocation**: Account state changes can invalidate tokens
- **Audit Trail**: All state changes logged for security monitoring
- **Admin Oversight**: Administrative controls for account management

### OAuth Security
- **Scope Limitations**: Account state affects available OAuth scopes
- **Client Binding**: OAuth authorizations tied to account status
- **Consent Management**: Account state affects consent validity
- **Token Security**: Account deactivation revokes OAuth tokens

### Compliance Features
- **Data Retention**: Inactive accounts preserve data per compliance requirements
- **Audit Logging**: All account state changes logged
- **Administrative Controls**: Proper separation of duties for account management
- **User Rights**: Account deletion removes all associated data

This account state system provides comprehensive user lifecycle management with strong security controls and seamless OAuth 2.1 integration.
