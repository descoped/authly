### **UI/UX Plan for Authly Admin Frontend**

**Date:** 2025-07-12  
**Status:** UI/UX Planning Document  
**Category:** Frontend Implementation Guide  
**Implementation Status:** Not Started

This plan organizes the user interface around the available API endpoints, focusing on a logical and secure workflow for administrators.

---

### **Part 1: Core Authentication Flow**

This is the initial experience for any user trying to access the admin panel.

**1. Login Page (`/login`)**
*   **Purpose:** The entry point for all administrators.
*   **UI:** A simple form with "Username" and "Password" fields and a "Login" button.
*   **API Interaction:**
    *   On submit, it calls `POST /api/v1/auth/token` with `grant_type: "password"`.
    *   **Success:** Securely stores the returned `access_token` and `refresh_token`.
    *   **Failure:** Displays an "Invalid credentials" error message.

**2. Post-Login Password Check (Mandatory Step)**
*   **Purpose:** Enforce the security requirement of changing the default admin password.
*   **Logic:**
    1.  Immediately after a successful login, the frontend will call `GET /api/v1/users/me` to fetch the current user's details.
    2.  It will then check for a condition that indicates a default password is in use.
        *   **Assumption:** The backend needs to provide a way to signal this. The ideal solution is a specific boolean flag (e.g., `requires_password_change: true`) in the `UserResponse` model from the `/api/v1/users/me` endpoint.
*   **UI Flow:**
    *   **If Password Change is Required:** The application will immediately display a **"Change Password" modal or redirect to a dedicated page (`/force-password-change`)**. The user will be blocked from accessing any other part of the application until they have successfully updated their password.
    *   **If Password is OK:** The user is redirected to the main Admin Dashboard.

**3. Forced Password Change View (`/force-password-change` or Modal)**
*   **Purpose:** A restricted view for updating the mandatory password.
*   **UI:** A form with "New Password" and "Confirm New Password" fields.
*   **API Interaction:**
    *   On submit, it calls `PUT /api/v1/users/{user_id}` (the `user_id` is retrieved from the `/users/me` call). The request body will contain the new `password`.
    *   **Success:** The user is redirected to the Admin Dashboard.
    *   **Failure:** Displays a relevant error message.

---

### **Part 2: Main Application Layout & Navigation**

Once authenticated and the password check is passed, the user will see the main application layout.

*   **Layout:** A standard dashboard layout with a persistent sidebar for navigation and a main content area. A "Logout" button will be present in the header or sidebar.
*   **Logout:** The "Logout" button will call `POST /api/v1/auth/logout`, clear the stored tokens, and redirect to the `/login` page.

**Sidebar Navigation Structure:**

*   **Dashboard** (`/`)
*   **User Management** (`/users`)
*   **OAuth Clients** (`/clients`)
*   **OAuth Scopes** (`/scopes`)
*   **System Status** (`/status`)

---

### **Part 3: UI Views and API Mapping**

Here is a breakdown of each section in the navigation.

**1. Dashboard (`/`)**
*   **Purpose:** Provide a high-level overview of the system's activity and health.
*   **Potential Components:**
    *   Welcome message.
    *   Quick stats (e.g., Total Users, Active Clients).
    *   Link to System Status page.
*   **API Interaction:**
    *   `GET /admin/users` (for user count)
    *   `GET /admin/clients` (for client count)

**2. User Management (`/users`)**
*   **Purpose:** Manage all user accounts in the system.
*   **Views:**
    *   **User List View (`/users`):**
        *   **UI:** A table displaying users with columns for Username, Email, Active status, Verified status, and Admin status. Will include a "Create User" button.
        *   **API:** `GET /api/v1/users/` with pagination controls.
    *   **Create/Edit User View (`/users/new`, `/users/:id/edit`):**
        *   **UI:** A form to create or update user details.
        *   **API (Create):** `POST /api/v1/users/`
        *   **API (Update):** `PUT /api/v1/users/{user_id}`
    *   **User Actions (on the list view):**
        *   **Verify:** Button to call `PUT /api/v1/users/{user_id}/verify`.
        *   **Delete:** Button with confirmation to call `DELETE /api/v1/users/{user_id}`.

**3. OAuth Clients (`/clients`)**
*   **Purpose:** Full CRUD management for OAuth 2.1 clients.
*   **Views:**
    *   **Client List View (`/clients`):**
        *   **UI:** A table listing clients with columns for Client Name, Client ID, and Type (Public/Confidential). Includes a "Register New Client" button.
        *   **API:** `GET /admin/clients`.
    *   **Client Details/Edit View (`/clients/:id`):**
        *   **UI:** A detailed view with multiple tabs or sections:
            *   **General Settings:** Client name, type, redirect URIs, etc.
            *   **OIDC Settings:** A dedicated section for OpenID Connect settings.
            *   **Credentials:** Display the Client ID and provide a button to regenerate the secret.
        *   **API (Get):** `GET /admin/clients/{client_id}`
        *   **API (Update):** `PUT /admin/clients/{client_id}`
        *   **API (OIDC):** `GET` and `PUT` on `/admin/clients/{client_id}/oidc`.
        *   **API (Regenerate Secret):** `POST /admin/clients/{client_id}/regenerate-secret`.

**4. OAuth Scopes (`/scopes`)**
*   **Purpose:** Manage OAuth scopes for defining permissions.
*   **Views:**
    *   **Scope List View (`/scopes`):**
        *   **UI:** A table listing scopes with columns for Scope Name, Description, and Default status. Includes a "Create Scope" button.
        *   **API:** `GET /admin/scopes`.
    *   **Create/Edit Scope View (`/scopes/new`, `/scopes/:name/edit`):**
        *   **UI:** A simple form for the scope name and description.
        *   **API (Create):** `POST /admin/scopes`.
        *   **API (Update):** `PUT /admin/scopes/{scope_name}`.
    *   **Delete Action:** Button with confirmation to call `DELETE /admin/scopes/{scope_name}`.

**5. System Status (`/status`)**
*   **Purpose:** Display detailed system configuration and health information for debugging and monitoring.
*   **UI:** A read-only view, likely using a formatted JSON viewer or definition lists to display the configuration data.
*   **API Interaction:** `GET /admin/status`.
