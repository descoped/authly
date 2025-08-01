# Release Process

Automated PyPI and Docker Hub releases via GitHub Actions.

## Pre-Release Preparation

Before creating a release, ensure:

- [ ] All intended changes are merged into the `master` branch
- [ ] Tests are passing on the latest commit
- [ ] Version in `pyproject.toml` matches the intended release version
- [ ] Documentation is up to date

## Version Management

#### Semantic Versioning
Follow [SemVer](https://semver.org/) guidelines:
- **MAJOR** (`v1.0.0 → v2.0.0`): Breaking changes
- **MINOR** (`v1.0.0 → v1.1.0`): New features, backward compatible
- **PATCH** (`v1.0.0 → v1.0.1`): Bug fixes, backward compatible

#### Update Version
Update the version in `pyproject.toml`:
```toml
[project]
version = "0.5.2"  # New version without 'v' prefix
```

Commit this change:
```bash
git add pyproject.toml
git commit -m "Bump version to 0.5.2"
git push origin master
```

## Creating a Release

1. **Navigate to Releases**
   - Go to the repository on GitHub
   - Click on "Releases" in the right sidebar
   - Click "Create a new release"

2. **Configure the Release**
   - **Tag**: Enter the new tag (e.g., `v0.5.2`)
     - ⚠️ **Must follow pattern**: `v[0-9]+.[0-9]+.[0-9]+`
     - ✅ Valid: `v0.5.2`, `v1.0.0`, `v10.5.2`
     - ❌ Invalid: `0.5.2`, `v0.5`, `v0.5.2-beta`
   - **Target**: Select `master` branch
   - **Title**: `v0.5.2` (same as tag)
   - **Description**: Add release notes (see template below)

3. **Publish the Release**
   - Click "Publish release"
   - This triggers the automated workflow

## Automated Workflow

The GitHub Action workflow (`.github/workflows/release-pypi.yml`) automatically:

1. **Validates** the release:
   - Checks tag format matches regex `^v[0-9]+\.[0-9]+\.[0-9]+$`
   - Extracts version number (removes `v` prefix)
   - Verifies `pyproject.toml` version matches tag version

2. **Runs quality checks**:
   - Linting with `ruff check` and `ruff format --check`
   - Full test suite with coverage
   - Uploads coverage reports to Codecov

3. **Builds and publishes**:
   - Builds the package with `uv build`
   - Generates artifact attestation for supply chain security
   - Publishes to PyPI with `uv publish`
   - Uploads wheel as GitHub artifact

4. **Docker build and push**:
   - Downloads the built wheel artifact
   - Builds multi-platform Docker images (linux/amd64, linux/arm64)
   - Uses `USE_WHEEL=true` for optimized production builds
   - Pushes to Docker Hub with tags:
     - `descoped/authly:0.5.2` (exact version)
     - `descoped/authly:0.5` (minor version)
     - `descoped/authly:0` (major version)
     - `descoped/authly:latest` (latest release)

## Post-Release Verification

After the workflow completes:

- [ ] Check the [PyPI page](https://pypi.org/project/authly/) for the new version
- [ ] Check [Docker Hub](https://hub.docker.com/r/descoped/authly) for new image tags
- [ ] Test PyPI installation: `uv add authly==0.5.2`
- [ ] Test Docker image: `docker pull descoped/authly:0.5.2`
- [ ] Verify the GitHub Action workflow succeeded
- [ ] Monitor for any issues or bug reports

## Release Notes Template

Use this template for release descriptions:

```markdown
## What's Changed

### 🚀 New Features
- Feature description

### 🐛 Bug Fixes  
- Bug fix description

### 📚 Documentation
- Documentation updates

### 🔧 Internal Changes
- Internal improvements

### 📦 Dependencies
- Dependency updates

### 🐳 Docker Changes
- Multi-platform build improvements
- Image optimizations

**Full Changelog**: https://github.com/descoped/authly/compare/v0.5.1...v0.5.2
```

## Installation Verification

```bash
# PyPI
uv add authly==0.5.2

# Docker
docker pull descoped/authly:0.5.2
docker run -p 8000:8000 descoped/authly:0.5.2
```

## Docker Usage

```bash
# Production
docker run -d -p 8000:8000 \
  -e DATABASE_URL="postgresql://user:pass@host:5432/authly" \
  -e JWT_SECRET_KEY="your-secret" \
  descoped/authly:0.5.2

# Development
docker run -p 8000:8000 descoped/authly:latest serve --embedded --seed
```

## Troubleshooting

### Common Issues

#### Version Mismatch Error
```
❌ Version mismatch!
   pyproject.toml version: 0.5.1
   Git tag version: 0.5.2
```

**Solution**: Update `pyproject.toml` version to match the git tag, then create a new release.

#### Invalid Tag Format
```
❌ Invalid tag format: 0.5.2
Expected format: v[0-9]+.[0-9]+.[0-9]+ (e.g., v0.5.2)
```

**Solution**: Ensure the tag starts with `v` and follows semantic versioning.

#### PyPI Token Issues
```
❌ Authentication failed
```

**Solution**: Verify the `PYPI_API_TOKEN` secret is correctly configured in the repository settings.

#### Docker Hub Authentication Issues
```
❌ Login to Docker Hub failed
```

**Solution**: Verify `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets are correctly configured.

### Manual Release Recovery

If the automated workflow fails after creating the GitHub release:

1. **Check the workflow logs** for specific error details
2. **Fix the issue** (version mismatch, test failures, Docker build issues, etc.)
3. **Delete the failed release** and tag from GitHub
4. **Create a new release** with the corrected information

### Emergency Hotfix Process

For critical bug fixes:

1. Create a hotfix branch from the latest release tag
2. Apply the fix and update the patch version
3. Follow the standard release process
4. Consider backporting to maintenance branches if needed