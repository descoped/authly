# Advanced Troubleshooting Tools Guide

## System Monitoring

### Basic Commands
```bash
w                    # Who is logged in (standard Unix)
top / htop          # Process monitoring
iostat -x 1         # I/O statistics
vmstat 1            # Virtual memory stats
mpstat -P ALL 1     # Per-CPU statistics
sar -u 1 10         # System activity reporter
free -h             # Memory usage
df -h               # Disk usage
```

### Custom Functions
```bash
topmem              # Top 10 memory consumers
topcpu              # Top 10 CPU consumers
sysinfo             # System resource summary
pyinfo              # Python process inspection
dbcheck             # Database connection status
```

## Network Debugging

### Connection Analysis
```bash
netstat -antp       # All connections with PIDs
ss -antp            # Socket statistics (faster)
lsof -i             # List open network files
whoisport 8000      # Find process using port 8000
connections         # Show established connections
listening           # Show listening ports
connection_count    # Count connections by IP
```

### Network Tools
```bash
tcpdump -i any -nn -c 100         # Capture 100 packets
tcpdump -i any port 8000          # Monitor port 8000
nmap -sT localhost                 # TCP port scan
mtr google.com                     # Network path analysis
traceroute -n 8.8.8.8             # Trace network path
dig example.com                    # DNS lookup
nslookup example.com              # Alternative DNS lookup
```

### HTTP Monitoring
```bash
curl -I https://example.com       # Get headers only
curl -w "@curl-format.txt" URL    # Custom output format
monitor_endpoint http://localhost:8000/health  # Continuous monitoring
checkcert example.com              # Check SSL certificate
```

## Performance Profiling

### System Performance
```bash
iostat -x 1         # Extended I/O stats
iotop -o            # I/O by process
dstat -cdnmgyl      # Comprehensive stats
vmstat 1            # Virtual memory stats
sar -u 1 10         # CPU utilization
sar -r 1 10         # Memory utilization
sar -d 1 10         # Disk utilization
```

### Process Tracing
```bash
strace -p PID                      # Trace system calls
strace -f -e trace=network CMD     # Trace network calls
ltrace -p PID                      # Trace library calls
lsof -p PID                        # Files opened by process
```

### Python Profiling
```bash
py-spy top --pid PID               # Real-time Python profiling
py-spy record -o profile.svg -d 30 --pid PID  # Record flame graph
python -m cProfile -s cumulative script.py    # Profile script
python -m memory_profiler script.py           # Memory profiling
pyinstrument script.py             # Statistical profiler
```

## Log Analysis

### Application Logs
```bash
authly_errors       # Show Authly errors
tail -f /var/log/authly/*.log     # Follow Authly logs
grep ERROR /var/log/*.log         # Find all errors
grep -B5 -A5 "pattern" logfile    # Context around matches
```

### System Logs
```bash
dmesg               # Kernel messages
journalctl -xe      # System journal (if available)
tail -f /var/log/messages         # System messages
last -a             # Login history
lastlog             # Last login times
```

## Database Troubleshooting

### PostgreSQL
```bash
psql                # Direct database access
# In psql:
:stats              # Database statistics
:tables             # List all tables
\l                  # List databases
\dt                 # List tables
\d+ tablename       # Describe table
SELECT * FROM pg_stat_activity;    # Active queries
SELECT * FROM pg_locks;            # Lock information
```

### Redis/KeyDB
```bash
redis               # Direct cache access
# In redis-cli:
INFO memory         # Memory usage
INFO stats          # General statistics
MONITOR             # Real-time command monitoring
SLOWLOG GET 10      # Last 10 slow queries
CLIENT LIST         # Connected clients
KEYS authly:*       # Authly cache keys
```

## Python Debugging

### Interactive Debugging
```bash
python -m pdb script.py           # Start with debugger
python -m ipdb script.py          # Enhanced debugger
ipython                           # Interactive Python shell
```

### In-code debugging
```python
import pdb; pdb.set_trace()      # Breakpoint
import ipdb; ipdb.set_trace()    # Enhanced breakpoint
import traceback; traceback.print_stack()  # Print stack trace
```

### Memory Analysis
```python
# Memory profiling decorator
from memory_profiler import profile

@profile
def my_function():
    pass

# Run with: python -m memory_profiler script.py
```

## Container Debugging

### Docker Commands
```bash
docker logs authly-test           # Container logs
docker stats authly-test          # Resource usage
docker exec -it authly-test bash  # Shell access
docker inspect authly-test        # Full container info
```

### Inside Container
```bash
ps auxf             # Process tree
netstat -tuln       # Network listeners
env | sort          # Environment variables
mount | column -t   # Mounted filesystems
```

## Quick Diagnostics

### Health Checks
```bash
# System health
sysinfo             # Custom system summary
dbcheck             # Database connectivity
curl http://localhost:8000/health # API health

# Resource usage
topmem              # Top memory processes
topcpu              # Top CPU processes
openfiles           # Count of open files
```

### Performance Issues
```bash
# High CPU
top                 # Interactive process viewer
mpstat -P ALL 1     # Per-core CPU usage
ps aux --sort=-%cpu | head        # Top CPU processes

# High Memory
free -h             # Memory overview
ps aux --sort=-%mem | head        # Top memory processes
cat /proc/meminfo   # Detailed memory info

# High I/O
iotop -o            # I/O by process
iostat -x 1         # Disk I/O stats
lsof | grep REG | wc -l           # Open files count

# Network Issues
ss -s               # Socket summary
netstat -i          # Network interfaces
iftop               # Real-time bandwidth usage
```

## Common Scenarios

### API Not Responding
```bash
# Check if service is running
ps aux | grep authly
# Check if port is listening
lsof -i :8000
# Check logs
tail -n 100 /var/log/authly/*.log
# Test endpoint
curl -v http://localhost:8000/health
```

### Database Connection Issues
```bash
# Test PostgreSQL
psql -c "SELECT 1;"
# Test Redis
redis ping
# Check connections
ss -tan | grep -E "5432|6379"
```

### High Memory Usage
```bash
# Find memory hogs
topmem
# Python memory
pyinfo
# Database connections
psql -c "SELECT count(*) FROM pg_stat_activity;"
```

### Slow Performance
```bash
# System load
uptime
# I/O wait
iostat -x 1
# Database queries
psql -c "SELECT * FROM pg_stat_activity WHERE state != 'idle';"
# Redis slow queries
redis SLOWLOG GET 10
```

## Tips

1. **Always check basics first**: `sysinfo`, `dbcheck`, health endpoint
2. **Use custom functions**: `topmem`, `topcpu`, `whoisport`, etc.
3. **Monitor in real-time**: Most commands support continuous mode (add `1` for 1-second intervals)
4. **Combine tools**: `strace` + `tcpdump` for full picture
5. **Check logs**: Application logs often have the answer
6. **Use Python profilers**: `py-spy` for production, `cProfile` for development

## Aliases Reference

All common admin commands have short aliases:
- `w` - who is logged in
- `ps` - process list with tree
- `netstat` - network connections
- `ss` - socket statistics
- `lsof` - list open files
- `top` - uses htop if available
- `df` - disk free (human readable)
- `du` - disk usage (human readable)

Type `alias` to see all available aliases.