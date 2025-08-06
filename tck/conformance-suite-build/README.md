# Conformance Suite Build Strategy

This directory contains our build configuration for the OpenID Foundation conformance suite.
We DO NOT modify the upstream repository - all customizations are external.

## Directory Structure

```
tck/
├── conformance-suite-build/     # Our build configuration (THIS DIRECTORY)
│   ├── Dockerfile               # Multi-stage build
│   ├── docker-compose.yml      # Service orchestration
│   ├── nginx.conf              # HTTPS configuration
│   ├── certs/                  # SSL certificates
│   └── scripts/                # Our automation scripts
│
├── conformance-suite/           # CLONED REPO (DO NOT MODIFY)
│   └── [upstream code]          # Treat as read-only
│
└── scripts/                     # Our test automation
    ├── run-conformance-tests.py
    ├── conformance_client.py
    └── quick-test.py
```

## Build Options

### Option 1: Docker Multi-Stage Build (Recommended)
Builds conformance suite inside Docker without local modifications:

```bash
cd tck/conformance-suite-build
docker compose build
docker compose up -d
```

### Option 2: Pre-built JAR with Volume Mount
Uses the JAR built from cloned repo:

```bash
# Build JAR once
cd tck/conformance-suite
mvn clean package -DskipTests=true

# Run with volume mount
cd ../conformance-suite-build
docker compose -f docker-compose-prebuilt.yml up -d
```

### Option 3: Official Docker Image (When Available)
```bash
# Future: Use official image when published
docker pull openid/conformance-suite:latest
```

## Integration Strategy

### Principles:
1. **Never modify cloned repositories** - All customizations external
2. **Version control our configurations** - Track our Docker/build files
3. **Document dependencies clearly** - Specify exact versions
4. **Isolate from main codebase** - Keep in tck/ subdirectory
5. **Reproducible builds** - Anyone can rebuild from scratch

### Workflow:
1. Clone upstream repository (or use git submodule)
2. Apply our build configuration
3. Build in isolated environment
4. Run with our test configurations

## Git Strategy

### Option A: Git Submodules (Recommended)
```bash
# Add conformance suite as submodule
git submodule add https://gitlab.com/openid/conformance-suite.git tck/conformance-suite
git submodule update --init --recursive

# Pin to specific version
cd tck/conformance-suite
git checkout v5.1.0  # or specific commit
cd ../..
git add tck/conformance-suite
git commit -m "chore: pin conformance suite to v5.1.0"
```

### Option B: Build-time Clone
Clone during Docker build (current approach in Dockerfile)

### Option C: Git Subtree
For vendoring the code while tracking upstream

## Version Management

Track versions in `.conformance-version` file:
```
CONFORMANCE_SUITE_VERSION=v5.1.0
CONFORMANCE_SUITE_COMMIT=abc123def
BUILD_DATE=2025-08-06
```

## CI/CD Integration

The GitHub Actions workflow should:
1. Check if conformance suite exists
2. Clone/update to specified version
3. Build using our Dockerfile
4. Run tests
5. Archive results

## Development Workflow

```bash
# Fresh checkout
git clone https://github.com/yourorg/authly.git
cd authly

# Initialize conformance testing
make -C tck init  # Clones suite, builds JAR

# Start services
make -C tck start

# Run tests
make -C tck test

# Clean up
make -C tck clean
```

## Troubleshooting

### If conformance suite is missing:
```bash
cd tck
git clone https://gitlab.com/openid/conformance-suite.git
```

### If build fails:
```bash
# Use Docker build instead of local Maven
cd conformance-suite-build
docker compose build --no-cache
```

### If modifications were made to cloned repo:
```bash
cd tck/conformance-suite
git status  # Check modifications
git stash  # Save changes temporarily
git reset --hard origin/master  # Reset to upstream
```

## Best Practices

1. **Document all customizations** in this README
2. **Use environment variables** for configuration
3. **Keep build reproducible** - no local dependencies
4. **Test in CI** - Ensure fresh checkout works
5. **Version everything** - Pin all dependencies