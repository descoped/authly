# Prometheus Queries for Authly Monitoring

## Access Prometheus
- **URL**: http://localhost:9090
- **No authentication required** (in development mode)

## Useful Queries

### Basic Health Checks

#### Check if services are up
```promql
up
```
Shows 1 if service is up, 0 if down for all monitored services.

#### Check specific service
```promql
up{job="authly"}
```

### HTTP Metrics

#### Total requests by endpoint
```promql
sum by (endpoint) (authly_http_requests_total)
```

#### Request rate (last 5 minutes)
```promql
sum(rate(authly_http_requests_total[5m])) * 60
```
Shows requests per minute.

#### Error rate by endpoint
```promql
sum by (endpoint) (rate(authly_http_requests_total{status_code=~"4..|5.."}[5m]))
```

#### Success rate percentage
```promql
sum(rate(authly_http_requests_total{status_code=~"2.."}[5m])) 
/ 
sum(rate(authly_http_requests_total[5m])) 
* 100
```

#### Top 5 most requested endpoints
```promql
topk(5, sum by (endpoint) (authly_http_requests_total))
```

#### Requests by HTTP method
```promql
sum by (method) (authly_http_requests_total)
```

### PostgreSQL Metrics

#### Database connections
```promql
pg_stat_database_numbackends{datname="authly"}
```

#### Database size
```promql
pg_database_size_bytes{datname="authly"} / 1024 / 1024
```
Shows database size in MB.

#### Active queries
```promql
pg_stat_activity_count{datname="authly",state="active"}
```

#### Connection pool utilization
```promql
pg_stat_database_numbackends{datname="authly"} 
/ 
pg_settings_max_connections 
* 100
```

### Redis/KeyDB Metrics

#### Memory usage
```promql
redis_memory_used_bytes / 1024 / 1024
```
Shows memory usage in MB.

#### Connected clients
```promql
redis_connected_clients
```

#### Cache hit rate
```promql
rate(redis_keyspace_hits_total[5m]) 
/ 
(rate(redis_keyspace_hits_total[5m]) + rate(redis_keyspace_misses_total[5m])) 
* 100
```

#### Commands per second
```promql
rate(redis_commands_processed_total[1m])
```

### System Metrics

#### Prometheus memory usage
```promql
process_resident_memory_bytes{job="prometheus"} / 1024 / 1024
```

#### Scrape duration
```promql
scrape_duration_seconds
```

### Time Range Comparisons

#### Compare requests today vs yesterday
```promql
sum(increase(authly_http_requests_total[1d])) - sum(increase(authly_http_requests_total[1d] offset 1d))
```

#### Week-over-week comparison
```promql
sum(rate(authly_http_requests_total[1h])) / sum(rate(authly_http_requests_total[1h] offset 1w))
```

## Using Prometheus UI

1. **Graph Tab**: 
   - Enter queries and visualize them
   - Adjust time range with the controls
   - Use "Stacked" option for better visualization of multiple series

2. **Alerts Tab**:
   - View active alerts (if configured)
   - See alert states (pending, firing)

3. **Status Menu**:
   - **Targets**: Check if all services are being scraped successfully
   - **Configuration**: View active Prometheus configuration
   - **Rules**: See recording rules and alerts
   - **Service Discovery**: Check discovered targets

4. **Help Menu**:
   - Links to documentation
   - Query function reference

## Query Tips

### Use labels to filter
```promql
authly_http_requests_total{endpoint="/health", method="GET"}
```

### Aggregate functions
- `sum()` - Total across all series
- `avg()` - Average value
- `max()` / `min()` - Maximum/minimum values
- `count()` - Number of series
- `stddev()` - Standard deviation

### Rate vs Increase
- `rate()` - Per-second average rate of increase
- `increase()` - Total increase over time window
- `irate()` - Instant rate based on last two points

### Time windows
- `[5m]` - Last 5 minutes
- `[1h]` - Last hour
- `[1d]` - Last day
- `offset 1h` - Data from 1 hour ago

## Troubleshooting

### No data points
If queries return no data:
1. Check if the service is up: `up{job="authly"}`
2. Verify metrics exist: `authly_http_requests_total`
3. Try a wider time range: `[10m]` instead of `[1m]`
4. Check Prometheus targets: http://localhost:9090/targets

### Rate returns empty
Rate functions need at least 2 data points. If scrape interval is 15s, use at least `[1m]` time window.

### Debugging scraped metrics
See all metrics from a job:
```
curl -s http://localhost:8000/metrics | grep authly_
```

## Advanced Queries

### P95 latency (when histogram metrics are available)
```promql
histogram_quantile(0.95, 
  sum(rate(authly_http_request_duration_seconds_bucket[5m])) by (le)
)
```

### Alert threshold testing
```promql
sum(rate(authly_http_requests_total{status_code=~"5.."}[5m])) > 0.1
```
Shows when error rate exceeds 0.1 requests/second.

### Predict when disk will be full (linear regression)
```promql
predict_linear(pg_database_size_bytes{datname="authly"}[1h], 24*3600)
```
Predicts database size in 24 hours based on last hour's growth.

## Exporting Data

### Via API
```bash
# Get current value
curl 'http://localhost:9090/api/v1/query?query=up'

# Get time series data
curl 'http://localhost:9090/api/v1/query_range?query=up&start=2025-08-08T00:00:00Z&end=2025-08-09T00:00:00Z&step=1h'
```

### CSV Export
Use the Prometheus UI Graph tab, run your query, then click "Download CSV" button.

## Integration with Grafana

All these queries can be used in Grafana dashboards. The Prometheus datasource is already configured in Grafana at http://localhost:3000.