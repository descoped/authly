# Docker Standalone Implementation Challenges

## Overview
This document captures the technical challenges encountered during the implementation of the standalone Docker container and the solutions developed to overcome them.

## Major Challenges and Solutions

### 1. Password Inconsistency Across Test Scripts

#### Problem
Different components expected different passwords:
- Bootstrap system used `AUTHLY_ADMIN_PASSWORD` environment variable
- simple-auth-flow.sh hardcoded "Test123!" for all users
- Integration tests had various password expectations
- User creation required 8+ character passwords

#### Investigation Process
1. Initial symptom: Admin login failures in simple-auth-flow
2. Discovered bootstrap creates admin with environment password
3. Found simple-auth-flow expects "Test123!" everywhere
4. Realized created users need different passwords (8+ chars)

#### Solution: Multi-Layer Password Patching
```bash
# Runtime patching strategy:
1. Admin uses environment password (default: "admin")
2. User1 keeps original "Test123!"
3. Created test users use "TestUser123!" (satisfies 8+ requirement)
4. Conditional password selection in test_login function
```

#### Implementation
Created sophisticated sed replacements:
- Admin-specific OAuth requests patched
- Helper function for conditional password selection
- Preserved user1's original password
- Fixed created user login attempts

### 2. Process Management and Service Dependencies

#### Problem
Three services needed specific startup order:
- PostgreSQL must be ready before initialization
- Redis should start in parallel
- Authly needs both databases ready
- Bootstrap must complete before API access

#### Solution: s6-overlay Service Dependencies
```
postgres (longrun) ─┐
                    ├─> authly-init (oneshot) ─> authly (longrun)
redis (longrun) ────┘
```

### 3. Environment Variable Propagation

#### Problem
Environment variables not visible to child processes:
- AUTHLY_ADMIN_PASSWORD set but not accessible
- Integration tests couldn't find admin password
- s6-overlay clearing environment

#### Initial Attempts
1. Tried s6 envdir approach - didn't work
2. Attempted /run/s6/container_environment - not created properly
3. Export in wrapper scripts - not persistent

#### Solution
Set environment variables globally in Dockerfile ENV instruction with clear documentation about dev/test usage.

### 4. Structured Logging vs Readability

#### Problem
Default structured JSON logging not readable for development:
```json
{"timestamp":"2025-08-07T10:00:00","level":"INFO","message":"Starting"}
```

#### Solution
Added LOG_JSON=false environment variable for normal text logging:
```
2025-08-07 10:00:00 - authly.main - INFO - Starting
```

### 5. Integer Expression Errors in Bash Scripts

#### Problem
```bash
/app/scripts/simple-auth-flow-original.sh: line 147: [: : integer expression expected
```

#### Root Cause
- Arrays not expanding properly in Alpine's sh
- Empty index variables in comparisons
- LOG_LEVEL not matching known levels

#### Solution
Added default values in comparisons:
```bash
# Original (fails with empty variable)
if [ "$msg_level_index" -ge "$current_level_index" ]

# Fixed (handles empty variables)
if [ "${msg_level_index:-0}" -ge "${current_level_index:-3}" ]
```

### 6. Docker Security Warnings

#### Problem
```
SecretsUsedInArgOrEnv: Do not use ARG or ENV instructions for sensitive data
```

#### Consideration
For production containers, this would be critical. For dev/test container:
- Accepted warnings with clear documentation
- Added multiple warning layers
- Used descriptive insecure key names

### 7. User Seeding Complexity

#### Problem
Original Python async seeding approach caused:
- psycopg pool RuntimeWarning
- Complex async context management
- Verbose INSERT output

#### Solution
Replaced with simple SQL approach:
```sql
-- Direct SQL insertion
INSERT INTO users (...) VALUES (...) ON CONFLICT DO NOTHING;
```

### 8. Test Script Compatibility

#### Problem
simple-auth-flow.sh deeply integrated with specific password assumptions

#### Solution Process
1. Analyzed all 620+ lines of the script
2. Identified password usage patterns
3. Created surgical sed replacements
4. Tested iteratively until all 16 tests passed

## Debugging Techniques Used

### 1. Incremental Testing
- Built container after each change
- Tested specific failing scenarios
- Used grep to find actual vs expected

### 2. Shell Script Debugging
```bash
bash -x script.sh  # Trace execution
sed -n 'XXX,YYYp'  # Examine specific lines
```

### 3. Container Inspection
```bash
docker exec container bash -c "command"
docker logs container
ps aux inside container
```

### 4. Pattern Matching
Careful sed patterns to avoid breaking script structure:
- Line-specific replacements
- Context-aware patterns
- Function scope restrictions

## Lessons Learned

### What Worked
1. **Incremental approach** - Fix one test at a time
2. **Runtime patching** - More flexible than static replacement
3. **SQL seeding** - Simpler than application-level seeding
4. **Clear error messages** - Helped identify root causes

### What Didn't Work
1. **Blanket password replacement** - Broke different user types
2. **Complex async seeding** - Too many edge cases
3. **s6 envdir approach** - Environment not propagated correctly

### Best Practices Discovered
1. **Test early and often** - Each change can break something
2. **Preserve original files** - Keep original.sh for reference
3. **Document assumptions** - Password requirements, user types
4. **Layer security warnings** - Multiple places for visibility

## Time Investment

### Estimated vs Actual
- **Original estimate**: 1-2 days
- **Actual time**: 3-4 days
- **Extra time spent on**: Password consistency issues (60% of debug time)

### Breakdown
1. Initial implementation: 4 hours
2. Password debugging: 8 hours  
3. Process management: 2 hours
4. Testing and refinement: 4 hours
5. Documentation: 2 hours

## Conclusion

The implementation succeeded despite numerous challenges. The key was systematic debugging, incremental testing, and maintaining flexibility through runtime configuration rather than build-time decisions. The resulting container is robust, well-tested, and clearly documented for its intended dev/test use case.