# Authly Admin Frontend: Architectural Plan

**Date:** 2025-07-12  
**Status:** Architectural Planning Document  
**Category:** Future Implementation Guide  
**Implementation Status:** Not Started

This document outlines the architectural plan for creating a separate React-based admin frontend for the Authly service.

## 1. Core Principle: Separation of Concerns

To align with the future microservices architecture of Authly and to avoid creating a monolith, the admin frontend will be developed as a **completely separate project** from the Python backend.

- **Authly Backend:** Remains a pure, stateless API provider. Its sole responsibility is to serve the REST API endpoints.
- **Admin Frontend:** A standalone Single-Page Application (SPA) that consumes the backend API. It will have its own repository, development lifecycle, and deployment pipeline.

## 2. Technology Stack

The frontend will be built using a modern, industry-standard stack:

- **Framework:** **React** with **TypeScript** for type safety and scalability.
- **Build Tool:** **Vite** for a fast development experience and optimized production builds.
- **UI Component Library:** A robust library like **Material-UI (MUI)** or **Ant Design** will be used to accelerate development and ensure a consistent, professional UI.
- **State Management:** A suitable state management library (e.g., Redux Toolkit, Zustand) will be chosen as the application complexity grows.
- **Routing:** **React Router** for managing client-side navigation.

## 3. Project Structure

A new repository or directory will be created alongside the `authly` backend:

```
/project_root/
├── authly/                   # Existing Python backend
└── authly-admin-frontend/    # New React frontend project
```

## 4. Authentication

The frontend will act as a standard consumer of the Authly service, following best practices for web application security:

- **Client Type:** The frontend will be registered in Authly as a **public OAuth client**.
- **Authentication Flow:** It will implement the **Authorization Code Flow with PKCE**, which is the most secure flow for browser-based applications.
- **Token Storage:** JWTs (access and refresh tokens) returned from the token endpoint will be stored securely in the browser's `localStorage` or `sessionStorage`.

## 5. Development Workflow

The local development environment will consist of two separate, concurrent processes:

1.  **Backend Server:** The Authly Python/FastAPI server running on its own port (e.g., `http://localhost:8000`).
2.  **Frontend Dev Server:** The Vite development server running on a different port (e.g., `http://localhost:5173`).

To handle API requests and avoid CORS issues, the `vite.config.ts` file in the frontend project will be configured to **proxy** all API calls (e.g., requests to `/api/v1/*`) to the backend server.

## 6. Deployment Strategy

The frontend will be built into a set of static assets (HTML, CSS, JavaScript).

- **Production Build:** Running `npm run build` in the frontend project will generate a `dist` directory containing the optimized static files.
- **Serving:**
    - **Docker-Compose (Recommended):** A dedicated, lightweight **Nginx** container will be added to the `docker-compose.yml`. This Nginx container will:
        1.  Serve the static React application files.
        2.  Act as a reverse proxy, forwarding all API requests to the Authly backend container. This is a secure and standard pattern for production.
    - **Simple Docker:** For simpler deployments, the Authly backend's Docker image can be configured to also serve the static frontend files.

This decoupled architecture ensures a clean separation between the frontend and backend, aligns with the project's long-term vision, and provides a scalable and maintainable foundation for the admin interface.
