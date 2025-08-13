# CI/CD Integration Guide

## GitHub Actions Integration

The TCK is fully integrated with GitHub Actions for continuous compliance testing.

### Workflow Configuration

```yaml
# .github/workflows/conformance-tests.yml
name: OIDC Conformance Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  conformance:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Start services
      run: |
        cd tck
        docker compose --profile github-ci up -d
        sleep 10  # Wait for services to start
    
    - name: Run conformance tests
      run: |
        cd tck
        make validate
    
    - name: Generate reports
      if: always()
      run: |
        cd tck
        make report
    
    - name: Upload reports
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: conformance-reports
        path: tck/reports/latest/
    
    - name: Check compliance threshold
      run: |
        cd tck
        # Fail if compliance drops below 95%
        python -c "
        import json
        with open('reports/latest/conformance_results.json') as f:
            results = json.load(f)
        total = sum(1 for cat in results.values() for v in cat.values() if isinstance(v, bool))
        passed = sum(1 for cat in results.values() for v in cat.values() if v is True)
        compliance = (passed/total)*100
        print(f'Compliance: {compliance:.1f}%')
        exit(0 if compliance >= 95 else 1)
        "
    
    - name: Stop services
      if: always()
      run: |
        cd tck
        docker compose down
```

## Docker Compose Profiles

### CI Profile (`github-ci`)

The `github-ci` profile includes additional services needed for full conformance testing:

```yaml
services:
  mongodb:
    profiles:
      - github-ci
    image: mongo:4.4
    
  httpd:
    profiles:
      - github-ci
    build: ./httpd-ci
    
  conformance-suite:
    profiles:
      - github-ci
    image: ghcr.io/descoped/oidc-conformance-suite:latest
    depends_on:
      - mongodb
      - httpd
```

### Running in CI

```bash
# Start CI environment
docker compose --profile github-ci up -d

# Run tests
make validate

# Stop CI environment
docker compose --profile github-ci down
```

## Environment Variables

### Required for CI

```bash
# Authly configuration
AUTHLY_BASE_URL=http://host.docker.internal:8000
AUTHLY_ADMIN_PASSWORD=ci_admin_test_password

# Conformance suite (if using full suite)
CONFORMANCE_IMAGE=ghcr.io/descoped/oidc-conformance-suite:latest
```

### Optional

```bash
# Report output directory
TCK_REPORTS_DIR=reports/latest

# Test verbosity
TCK_VERBOSE=true
```

## Artifact Management

### Report Artifacts

Generated reports are saved as artifacts for review:
- `SPECIFICATION_CONFORMANCE.md` - Human-readable results
- `ACTIONABLE_ITEMS.md` - Issues to fix
- `COMPREHENSIVE_TEST_SUMMARY.md` - Executive summary
- `conformance_results.json` - Machine-readable results

### Accessing Artifacts

1. Go to Actions tab in GitHub
2. Select the workflow run
3. Download "conformance-reports" artifact
4. Extract and review reports

## Compliance Thresholds

### Setting Thresholds

Configure minimum compliance levels:

```python
# In workflow or script
MINIMUM_COMPLIANCE = 95  # Percentage

# Check compliance
compliance = calculate_compliance()
if compliance < MINIMUM_COMPLIANCE:
    print(f"❌ Compliance {compliance}% below threshold {MINIMUM_COMPLIANCE}%")
    exit(1)
```

### Gradual Improvement

Start with current compliance and gradually increase:
1. **Initial**: 90% (current baseline)
2. **Phase 1**: 95% (fix critical issues)
3. **Phase 2**: 98% (fix high priority)
4. **Target**: 100% (full compliance)

## Integration with Other CI Systems

### Jenkins

```groovy
pipeline {
    agent any
    
    stages {
        stage('Setup') {
            steps {
                sh 'cd tck && docker compose --profile github-ci up -d'
            }
        }
        
        stage('Test') {
            steps {
                sh 'cd tck && make validate'
            }
        }
        
        stage('Report') {
            steps {
                sh 'cd tck && make report'
                archiveArtifacts artifacts: 'tck/reports/latest/**'
            }
        }
    }
    
    post {
        always {
            sh 'cd tck && docker compose down'
        }
    }
}
```

### GitLab CI

```yaml
conformance:
  stage: test
  services:
    - docker:dind
  script:
    - cd tck
    - docker compose --profile github-ci up -d
    - make validate
    - make report
  artifacts:
    paths:
      - tck/reports/latest/
    when: always
  after_script:
    - cd tck && docker compose down
```

## Performance Optimization

### Caching

Cache Docker images and layers:

```yaml
- name: Setup Docker Buildx
  uses: docker/setup-buildx-action@v2
  with:
    cache-from: type=gha
    cache-to: type=gha,mode=max
```

### Parallel Execution

Run independent tests in parallel:

```bash
# Run multiple test categories concurrently
make validate &
make test-plans &
wait
```

### Conditional Testing

Skip tests based on changes:

```bash
# Only run if OIDC code changed
if git diff --name-only HEAD^ | grep -E "(oauth|oidc|token)"; then
    make validate
fi
```

## Monitoring and Alerts

### Slack Notifications

```yaml
- name: Notify Slack
  if: failure()
  uses: slack-notify@v1
  with:
    webhook: ${{ secrets.SLACK_WEBHOOK }}
    message: "OIDC Conformance dropped below threshold"
```

### Status Badges

Add to README:
```markdown
![Conformance](https://img.shields.io/badge/OIDC%20Compliance-98%25-green)
```

## Best Practices

1. **Run on every PR** - Catch compliance issues early
2. **Archive reports** - Keep history of compliance
3. **Set gradual thresholds** - Improve incrementally
4. **Monitor trends** - Track compliance over time
5. **Fast feedback** - Use lightweight TCK for quick checks
6. **Full validation** - Run complete suite weekly/monthly

## Troubleshooting CI Issues

### Services Not Starting

```bash
# Check service logs
docker compose --profile github-ci logs

# Verify port availability
netstat -tulpn | grep -E "(8000|8443|27017)"
```

### Network Issues

```bash
# Use service names in CI
AUTHLY_BASE_URL=http://authly:8000

# Or use host networking
docker compose --profile github-ci up --network host
```

### Timeout Issues

```yaml
# Increase timeout for slow CI runners
- name: Wait for services
  run: sleep 30  # Increase from 10
```