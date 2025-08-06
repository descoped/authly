# External Dependencies Strategy

## Problem Statement
We need the OpenID Foundation conformance suite but should NOT modify the upstream repository.

## Solution Architecture

```
tck/
├── conformance-suite/           # EXTERNAL - Cloned from upstream (NOT in git)
│   └── [upstream code]          # Treat as READ-ONLY
│
├── conformance-suite-build/     # OUR CODE - Build configurations (IN git)
│   ├── Dockerfile              # Multi-stage build
│   ├── docker-compose.yml     # Service orchestration
│   ├── nginx.conf             # HTTPS configuration
│   └── certs/                 # SSL certificates
│
├── scripts/                     # OUR CODE - Test automation (IN git)
│   ├── run-conformance-tests.py
│   ├── conformance_client.py
│   └── quick-test.py
│
└── Makefile                     # OUR CODE - Automation (IN git)
```

## Key Principles

1. **Never modify external repositories**
   - The `conformance-suite/` directory is cloned from upstream
   - Any modifications go in `conformance-suite-build/`

2. **Clear separation**
   - External code: `conformance-suite/` (gitignored)
   - Our code: Everything else (tracked in git)

3. **Reproducible builds**
   - Fresh checkout can rebuild everything
   - No hidden dependencies

## Workflow for Fresh Checkout

```bash
# Clone Authly
git clone https://github.com/yourorg/authly.git
cd authly

# Initialize TCK (clones conformance suite, builds JAR)
cd tck
make init

# Start everything
cd ..
./scripts/start-with-tck.sh

# Or use Docker Compose
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.tck.yml up -d
```

## Git Configuration

### What's in Git:
- `tck/conformance-suite-build/` - Our build configurations
- `tck/scripts/` - Our test scripts
- `tck/Makefile` - Our automation
- `tck/.gitignore` - Excludes conformance-suite/

### What's NOT in Git:
- `tck/conformance-suite/` - External dependency
- `tck/results/` - Test results
- `*.jar` files - Built artifacts

## CI/CD Integration

GitHub Actions should:
```yaml
- name: Initialize TCK
  run: |
    cd tck
    make init  # Clones and builds conformance suite
    
- name: Run Tests
  run: |
    cd tck
    make test
```

## Versioning Strategy

To pin to a specific version, edit Makefile:
```makefile
CONFORMANCE_VERSION := v5.1.0  # or specific commit hash
```

## Troubleshooting

### If conformance-suite has local changes:
```bash
cd tck
make reset  # Removes all local changes
```

### If build fails:
```bash
cd tck
make clean  # Clean everything
make init   # Start fresh
```

### To update to latest upstream:
```bash
cd tck
make update
```

## Docker Build Options

### Option 1: Pre-built JAR (current)
Requires cloning and building JAR locally, then mounting in Docker.

### Option 2: Multi-stage Docker build (future)
Build everything in Docker without local dependencies:
```dockerfile
FROM maven:3-eclipse-temurin-17 AS builder
RUN git clone https://gitlab.com/openid/conformance-suite.git
RUN mvn clean package -DskipTests=true
...
```

### Option 3: Git Submodules (alternative)
```bash
git submodule add https://gitlab.com/openid/conformance-suite.git tck/conformance-suite
```

## Benefits of This Approach

1. **Clean separation** - External code never mixed with ours
2. **No accidental commits** - Can't accidentally commit upstream changes
3. **Easy updates** - Pull latest from upstream anytime
4. **Reproducible** - Anyone can rebuild from scratch
5. **CI-friendly** - Works in automated environments
6. **Version control** - Our configurations are tracked

## Migration from Old Structure

If you have the old structure with modifications in conformance-suite/:
```bash
cd tck/conformance-suite
git stash  # Save your changes
cd ..
make reset  # Reset to upstream
# Move your changes to conformance-suite-build/
```