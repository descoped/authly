# Redis/KeyDB Access Guide for Authly

## Quick Access

Just type `redis` or `keydb` to connect:

```bash
authly> redis
127.0.0.1:6379> PING
PONG
```

## Common Commands for Authly

### Check What's Stored
```bash
# List all keys
KEYS *

# List Authly-specific keys
KEYS authly:*

# Count all keys
DBSIZE

# Get database info
INFO keyspace
```

### Rate Limiting Data
```bash
# Check rate limit keys
KEYS authly:rate:*

# Get specific rate limit
GET authly:rate:login:192.168.1.1

# Check TTL on rate limit
TTL authly:rate:login:192.168.1.1
```

### Session/Token Data
```bash
# Find session keys
KEYS authly:session:*

# Find token keys  
KEYS authly:token:*

# Get token data
GET authly:token:[token-id]
```

### Monitoring
```bash
# Watch all commands in real-time
MONITOR

# Get memory usage
INFO memory

# Get client connections
INFO clients

# Get statistics
INFO stats
```

### Cache Management
```bash
# Clear all data (CAREFUL!)
FLUSHALL

# Clear current database
FLUSHDB

# Set test data
SET test:key "test value"
EXPIRE test:key 60

# Get with TTL
GET test:key
TTL test:key
```

## Interactive Features

KeyDB CLI supports:
- **Tab completion** for commands
- **Command hints** as you type
- **History** with arrow keys
- **Pattern matching** with KEYS
- **Pipelining** for bulk operations

## Useful Patterns

### Check if rate limited
```bash
authly> redis
127.0.0.1:6379> KEYS authly:rate:*
(empty array)  # No one is rate limited

127.0.0.1:6379> KEYS authly:rate:*
1) "authly:rate:login:10.0.0.1"  # Someone is rate limited
```

### Monitor activity
```bash
authly> redis --stat  # Shows rolling statistics
```

### Scan large keyspaces
```bash
authly> redis --scan --pattern 'authly:*'
```

### Check memory usage
```bash
authly> redis --bigkeys  # Find large keys
authly> redis --memkeys  # Analyze memory usage
```

## Notes

- Authly uses KeyDB (Redis-compatible) for:
  - Rate limiting
  - Session storage (if configured)
  - Token blacklisting (if configured)
  - Temporary caches

- Default configuration:
  - No password required (development mode)
  - Listening on localhost:6379
  - Database 0 is used

- The data is ephemeral by default (not persisted to disk)