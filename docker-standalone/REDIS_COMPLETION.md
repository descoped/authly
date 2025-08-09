# Redis/KeyDB Tab Completion Guide

## Built-in Completion

KeyDB CLI (redis-cli) includes automatic tab completion using linenoise library.

## What Works

### Command Completion
When you start typing a command and press TAB:
- `SE[TAB]` → Shows: SET, SETEX, SETNX, SETBIT, SETRANGE
- `G[TAB]` → Shows: GET, GETBIT, GETRANGE, GETSET, GEOADD, etc.
- `H[TAB]` → Shows: HGET, HSET, HMGET, HMSET, HKEYS, etc.

### Subcommand Completion
For multi-part commands:
- `CONFIG [TAB]` → Shows: GET, SET, RESETSTAT, REWRITE
- `CLIENT [TAB]` → Shows: LIST, KILL, GETNAME, SETNAME
- `SCRIPT [TAB]` → Shows: LOAD, EXISTS, FLUSH, KILL

### INFO Sections
- `INFO [TAB]` → Shows: server, clients, memory, persistence, stats, replication, cpu, keyspace

## Testing Completion

To test if tab completion is working:

```bash
# Enter Redis CLI
docker exec -it authly-test redis

# In the Redis prompt, try:
127.0.0.1:6379> SE[TAB]          # Should show SET commands
127.0.0.1:6379> CONFIG G[TAB]     # Should complete to CONFIG GET
127.0.0.1:6379> INFO mem[TAB]     # Should complete to INFO memory
```

## Features Available

✅ **Command name completion** - All Redis commands
✅ **Subcommand completion** - Multi-part commands
✅ **Command hints** - Shows syntax hints
✅ **History navigation** - Up/down arrows for command history
✅ **Reverse search** - Ctrl+R to search history
✅ **Word navigation** - Ctrl+A/E for line start/end
✅ **Clear screen** - Ctrl+L to clear

## Notes

- Tab completion requires interactive mode (`docker exec -it`)
- Completion is case-insensitive
- Press TAB twice to see all possibilities
- Use arrow keys to navigate suggestions

## Common Patterns

```bash
# Quick command lookup
127.0.0.1:6379> Z[TAB][TAB]      # Shows all Z* commands (ZADD, ZCARD, etc.)

# Check available INFO sections  
127.0.0.1:6379> INFO [TAB][TAB]  # Shows all INFO sections

# Explore CONFIG options
127.0.0.1:6379> CONFIG GET [TAB][TAB]  # Shows configuration parameters
```

The completion is less sophisticated than PostgreSQL's (no table/key name completion), but it covers all Redis commands effectively!