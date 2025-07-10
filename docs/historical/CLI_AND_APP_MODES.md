# Authly Operational Modes

## Authly must support these modes:

### 1. **Web Service Mode** (Default)
Run Authly as a production-ready OAuth 2.1 authorization server with FastAPI/uvicorn
```bash
python -m authly                           # Default: runs web service on 0.0.0.0:8000
python -m authly serve                     # Explicit web service mode
python -m authly serve --host 127.0.0.1 --port 8080  # Custom host/port
python -m authly serve --workers 4         # Multi-worker production mode
```

### 2. **Embedded Development Mode**
Run Authly with embedded PostgreSQL container for development/testing
```bash
python -m authly serve --embedded          # Starts PostgreSQL container + web service
python -m authly serve --embedded --seed   # Also seeds test data
```

### 3. **Admin CLI Mode**
Administrative operations through integrated CLI (direct database access initially, API-based later)
```bash
python -m authly admin status              # System status (from src/authly/admin/cli.py)
python -m authly admin client list         # List OAuth clients (from src/authly/admin/client_commands.py)
python -m authly admin client create       # Create OAuth client (from src/authly/admin/client_commands.py)
python -m authly admin scope list          # List OAuth scopes (from src/authly/admin/scope_commands.py)
python -m authly admin scope create        # Create OAuth scope (from src/authly/admin/scope_commands.py)

# Current CLI entry point (will be integrated):
authly-admin status                         # Current separate CLI entry
```

### 4. **Database Management Mode** [POSTPONED]
Database initialization and migration commands

**Status**: [POSTPONED] - Database initialization should happen automatically during startup if schema doesn't exist. This mode is postponed to keep focus on core features.

```bash
# POSTPONED - Database will auto-initialize on startup
python -m authly db init                   # Initialize database schema  
python -m authly db migrate                # Run migrations
python -m authly db seed                   # Seed initial data
python -m authly db bootstrap              # Bootstrap admin user and scopes
```

**Rationale**: Auto-initialization is sufficient for current needs. Manual database management commands can be added in a future phase if needed.

### 5. **Library Mode**
Import and use Authly as a Python library in other applications
```python
from authly import Authly
from authly.config import AuthlyConfig

# Initialize and use programmatically
pool = await create_pool()
authly = Authly.initialize(pool, config)
```

## Architecture Implications

### Unified Entry Point
- Single `__main__.py` that handles all modes
- Click-based CLI for command routing
- Shared initialization code across all modes

### Embedded Components
- FastAPI app factory in core Authly
- Uvicorn runner as part of Authly
- Database lifecycle management built-in
- CLI commands integrated, not separate

### Benefits
- No duplication between main.py and authly-embedded.py
- Consistent behavior across all deployment scenarios
- Single codebase to maintain and test
- Better developer experience with unified commands