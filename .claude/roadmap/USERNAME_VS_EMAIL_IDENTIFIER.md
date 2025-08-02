# Tech Note: Transitioning from Username to Email as Primary User Identifier

**Date:** 2025-07-12  
**Status:** Planning Document  
**Category:** Future Enhancement Proposal  
**Implementation Status:** Not Started

## 1. Executive Summary

This document evaluates the feasibility and impact of transitioning Authly's user identification system from a `username`-based model to an `email`-based model. The primary driver for this evaluation is the user experience goal of simplifying login to a standard "email and password" flow, which is common in modern web applications.

**Conclusion:** The transition is **highly recommended** and **fully compatible** with the existing architecture, including the OAuth 2.1 and future OIDC implementations. The system is designed in a way that makes this change feasible. We present two implementation options: a simple, no-change workaround and a more involved, "clean" refactoring.

## 2. Current Implementation

Authly's `users` table currently defines both `username` and `email` as separate, unique fields.

```sql
-- current users table schema
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    -- ... other fields
);
```

This design forces the system to manage two distinct user identifiers. While flexible, it can lead to a user experience that requires users to remember a separate username, which is what we aim to avoid.

## 3. Compatibility with OAuth 2.1 and OIDC

A key consideration is whether this change would impact our standards compliance.

- **OAuth 2.1:** The OAuth 2.1 specification is concerned with the "Resource Owner" and does not dictate *how* the authorization server identifies that owner. The method of authentication (username, email, etc.) is an internal implementation detail of Authly.
- **OIDC (OpenID Connect):** OIDC builds on OAuth and uses a standard claim, `sub` (subject), to provide a stable, unique identifier for the user. This `sub` claim is intentionally opaque and corresponds to the user's `id` (UUID) in our database, not their username or email.

Therefore, changing the login identifier from `username` to `email` has **no negative impact** on our OAuth or OIDC capabilities. The system will continue to issue standards-compliant tokens with the user's UUID as the `sub`.

## 4. Implementation Options

We have two primary paths to achieve this goal.

### Option 1: The Workaround (No Backend Changes)

This approach involves enforcing a business rule where the `username` field is always populated with the user's `email` address.

-   **User Registration**: The user's email is saved to both the `email` and `username` fields.
-   **User Login**: The user enters their email, which is sent to the API's `username` field, and authentication proceeds as normal.

**Pros:**
- Requires zero backend code changes.
- Fast to implement.

**Cons:**
- Creates redundant data in the database.
- Relies on consistent enforcement in all user-creation logic.
- Is not a "clean" architectural solution.

### Option 2: The Clean Refactor (Backend Changes Required)

This is the recommended long-term solution. It involves removing the `username` field entirely and making `email` the sole identifier.

**Plan:**

1.  **Database Schema Change**: Modify `docker-postgres/init-db-and-user.sql` to remove the `username` column from the `users` table.
2.  **Pydantic Models**: Remove `username` from all user-related models in `src/authly/users/models.py`.
3.  **Repository Layer**: Update `src/authly/users/repository.py` to replace username-based lookups (e.g., `get_by_username`) with email-based lookups (`get_by_email`).
4.  **Service Layer**: Update `src/authly/users/service.py` to remove any logic that references `username`.
5.  **API Layer**: Modify the authentication endpoint in `src/authly/api/auth_router.py` to use `email` from the login form for user lookup.
6.  **CLI and Bootstrap**: Update the admin CLI (`src/authly/admin/`) and the bootstrap seeding script (`src/authly/bootstrap/admin_seeding.py`) to operate on `email` instead of `username`.

**Pros:**
- Aligns the database and codebase with the desired user experience.
- Eliminates data redundancy.
- More maintainable in the long run.

**Cons:**
- Requires a coordinated refactoring effort across multiple files.
- Involves a database migration for existing systems.

## 5. Recommendation

For a robust, maintainable, and clean system, **Option 2 (The Clean Refactor) is the recommended path forward.** It aligns the technical implementation with the product vision.

If speed is the absolute priority, Option 1 provides a functional, immediate solution, but it should be considered a temporary measure before a proper refactoring is undertaken.
