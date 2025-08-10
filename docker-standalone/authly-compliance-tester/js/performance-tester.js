/**
 * Performance Testing Module
 * Load and stress testing for Authly endpoints
 */

class PerformanceTester {
    constructor(config, tester) {
        this.config = config;
        this.tester = tester;
        this.metrics = {
            requestCount: 0,
            successCount: 0,
            errorCount: 0,
            avgResponseTime: 0,
            minResponseTime: Infinity,
            maxResponseTime: 0,
            percentiles: {},
            throughput: 0
        };
        this.responseTimes = [];
    }
    
    /**
     * Run load test on specific endpoint
     */
    async loadTest(endpoint, options = {}) {
        const {
            concurrent = 10,
            duration = 30000, // 30 seconds
            rampUp = 5000, // 5 seconds ramp up
            method = 'GET',
            headers = {},
            body = null
        } = options;
        
        this.tester.addLog(`Starting load test: ${endpoint}`, 'info');
        this.tester.addLog(`Concurrent: ${concurrent}, Duration: ${duration}ms`, 'info');
        
        const startTime = Date.now();
        const endTime = startTime + duration;
        const rampUpInterval = rampUp / concurrent;
        
        const workers = [];
        
        // Ramp up workers gradually
        for (let i = 0; i < concurrent; i++) {
            await this.sleep(rampUpInterval);
            
            const worker = this.runWorker(endpoint, {
                method,
                headers,
                body,
                endTime
            });
            
            workers.push(worker);
        }
        
        // Wait for all workers to complete
        await Promise.all(workers);
        
        // Calculate final metrics
        this.calculateMetrics();
        
        return this.metrics;
    }
    
    /**
     * Run stress test to find breaking point
     */
    async stressTest(endpoint, options = {}) {
        const {
            startConcurrent = 5,
            maxConcurrent = 100,
            step = 5,
            duration = 10000, // 10 seconds per level
            targetSuccessRate = 0.95,
            targetResponseTime = 1000 // 1 second
        } = options;
        
        this.tester.addLog(`Starting stress test: ${endpoint}`, 'info');
        
        let concurrent = startConcurrent;
        let breakingPoint = null;
        
        while (concurrent <= maxConcurrent && !breakingPoint) {
            this.tester.addLog(`Testing with ${concurrent} concurrent connections...`, 'info');
            
            // Reset metrics for this level
            this.resetMetrics();
            
            // Run load test at this level
            await this.loadTest(endpoint, {
                concurrent,
                duration,
                rampUp: 1000
            });
            
            // Check if we've hit breaking point
            const successRate = this.metrics.successCount / this.metrics.requestCount;
            
            if (successRate < targetSuccessRate || this.metrics.avgResponseTime > targetResponseTime) {
                breakingPoint = {
                    concurrent: concurrent - step,
                    successRate,
                    avgResponseTime: this.metrics.avgResponseTime,
                    reason: successRate < targetSuccessRate ? 'Success rate dropped' : 'Response time exceeded'
                };
                
                this.tester.addLog(`Breaking point found at ${concurrent} concurrent`, 'warning');
            } else {
                concurrent += step;
            }
        }
        
        return {
            breakingPoint: breakingPoint || {
                concurrent: maxConcurrent,
                successRate: this.metrics.successCount / this.metrics.requestCount,
                avgResponseTime: this.metrics.avgResponseTime,
                reason: 'Max concurrent reached without breaking'
            },
            finalMetrics: this.metrics
        };
    }
    
    /**
     * Run spike test
     */
    async spikeTest(endpoint, options = {}) {
        const {
            baseConcurrent = 5,
            spikeConcurrent = 50,
            baselineDuration = 10000, // 10 seconds
            spikeDuration = 5000, // 5 seconds
            recoveryDuration = 10000 // 10 seconds
        } = options;
        
        this.tester.addLog(`Starting spike test: ${endpoint}`, 'info');
        
        const results = {
            baseline: {},
            spike: {},
            recovery: {}
        };
        
        // Baseline phase
        this.tester.addLog('Running baseline phase...', 'info');
        this.resetMetrics();
        await this.loadTest(endpoint, {
            concurrent: baseConcurrent,
            duration: baselineDuration
        });
        results.baseline = { ...this.metrics };
        
        // Spike phase
        this.tester.addLog('Running spike phase...', 'info');
        this.resetMetrics();
        await this.loadTest(endpoint, {
            concurrent: spikeConcurrent,
            duration: spikeDuration,
            rampUp: 1000
        });
        results.spike = { ...this.metrics };
        
        // Recovery phase
        this.tester.addLog('Running recovery phase...', 'info');
        this.resetMetrics();
        await this.loadTest(endpoint, {
            concurrent: baseConcurrent,
            duration: recoveryDuration
        });
        results.recovery = { ...this.metrics };
        
        return results;
    }
    
    /**
     * Run endurance/soak test
     */
    async enduranceTest(endpoint, options = {}) {
        const {
            concurrent = 10,
            duration = 300000, // 5 minutes
            checkInterval = 30000 // Check metrics every 30 seconds
        } = options;
        
        this.tester.addLog(`Starting endurance test: ${endpoint}`, 'info');
        this.tester.addLog(`Duration: ${duration / 1000} seconds`, 'info');
        
        const startTime = Date.now();
        const endTime = startTime + duration;
        const checkpoints = [];
        
        // Start continuous load
        const workers = [];
        for (let i = 0; i < concurrent; i++) {
            workers.push(this.runWorker(endpoint, {
                endTime,
                continuous: true
            }));
        }
        
        // Monitor metrics at intervals
        while (Date.now() < endTime) {
            await this.sleep(checkInterval);
            
            const checkpoint = {
                timestamp: Date.now() - startTime,
                metrics: { ...this.metrics }
            };
            
            checkpoints.push(checkpoint);
            
            this.tester.addLog(
                `Checkpoint: ${checkpoint.timestamp / 1000}s - ` +
                `Requests: ${this.metrics.requestCount}, ` +
                `Avg Response: ${this.metrics.avgResponseTime.toFixed(2)}ms`,
                'info'
            );
        }
        
        // Stop workers
        await Promise.all(workers);
        
        return {
            finalMetrics: this.metrics,
            checkpoints,
            memoryLeakDetected: this.detectMemoryLeak(checkpoints),
            performanceDegradation: this.detectPerformanceDegradation(checkpoints)
        };
    }
    
    /**
     * Test endpoint latency distribution
     */
    async latencyTest(endpoint, options = {}) {
        const {
            requests = 100,
            concurrent = 1
        } = options;
        
        this.tester.addLog(`Testing latency distribution: ${endpoint}`, 'info');
        
        this.resetMetrics();
        
        const batches = Math.ceil(requests / concurrent);
        
        for (let i = 0; i < batches; i++) {
            const batchPromises = [];
            
            for (let j = 0; j < concurrent && (i * concurrent + j) < requests; j++) {
                batchPromises.push(this.measureRequest(endpoint));
            }
            
            await Promise.all(batchPromises);
        }
        
        this.calculateMetrics();
        
        return {
            metrics: this.metrics,
            distribution: this.getLatencyDistribution(),
            percentiles: this.calculatePercentiles()
        };
    }
    
    /**
     * Run worker for continuous requests
     */
    async runWorker(endpoint, options = {}) {
        const { endTime, method = 'GET', headers = {}, body = null, continuous = false } = options;
        
        while (Date.now() < endTime) {
            await this.measureRequest(endpoint, { method, headers, body });
            
            if (!continuous) {
                // Add small random delay to simulate real traffic
                await this.sleep(Math.random() * 100);
            }
        }
    }
    
    /**
     * Measure single request
     */
    async measureRequest(endpoint, options = {}) {
        const startTime = performance.now();
        
        try {
            const { response } = await this.tester.makeRequest(endpoint, options);
            
            const responseTime = performance.now() - startTime;
            
            this.recordMetric(responseTime, response.ok);
            
            return { success: response.ok, responseTime };
        } catch (error) {
            const responseTime = performance.now() - startTime;
            
            this.recordMetric(responseTime, false);
            
            return { success: false, responseTime, error: error.message };
        }
    }
    
    /**
     * Record metric
     */
    recordMetric(responseTime, success) {
        this.metrics.requestCount++;
        
        if (success) {
            this.metrics.successCount++;
        } else {
            this.metrics.errorCount++;
        }
        
        this.responseTimes.push(responseTime);
        
        // Update min/max
        this.metrics.minResponseTime = Math.min(this.metrics.minResponseTime, responseTime);
        this.metrics.maxResponseTime = Math.max(this.metrics.maxResponseTime, responseTime);
        
        // Update running average
        this.metrics.avgResponseTime = 
            (this.metrics.avgResponseTime * (this.metrics.requestCount - 1) + responseTime) / 
            this.metrics.requestCount;
    }
    
    /**
     * Calculate final metrics
     */
    calculateMetrics() {
        if (this.responseTimes.length === 0) return;
        
        // Sort response times for percentile calculation
        this.responseTimes.sort((a, b) => a - b);
        
        // Calculate percentiles
        this.metrics.percentiles = this.calculatePercentiles();
        
        // Calculate throughput
        const totalTime = this.responseTimes.reduce((sum, time) => sum + time, 0);
        this.metrics.throughput = (this.metrics.requestCount / totalTime) * 1000; // requests per second
    }
    
    /**
     * Calculate percentiles
     */
    calculatePercentiles() {
        const percentiles = {};
        const percentileValues = [50, 75, 90, 95, 99];
        
        for (const p of percentileValues) {
            const index = Math.ceil((p / 100) * this.responseTimes.length) - 1;
            percentiles[`p${p}`] = this.responseTimes[index] || 0;
        }
        
        return percentiles;
    }
    
    /**
     * Get latency distribution
     */
    getLatencyDistribution() {
        const buckets = {
            '<100ms': 0,
            '100-250ms': 0,
            '250-500ms': 0,
            '500-1000ms': 0,
            '1-2s': 0,
            '2-5s': 0,
            '>5s': 0
        };
        
        for (const time of this.responseTimes) {
            if (time < 100) buckets['<100ms']++;
            else if (time < 250) buckets['100-250ms']++;
            else if (time < 500) buckets['250-500ms']++;
            else if (time < 1000) buckets['500-1000ms']++;
            else if (time < 2000) buckets['1-2s']++;
            else if (time < 5000) buckets['2-5s']++;
            else buckets['>5s']++;
        }
        
        // Convert to percentages
        const total = this.responseTimes.length;
        for (const bucket in buckets) {
            buckets[bucket] = ((buckets[bucket] / total) * 100).toFixed(2) + '%';
        }
        
        return buckets;
    }
    
    /**
     * Detect memory leak from checkpoints
     */
    detectMemoryLeak(checkpoints) {
        if (checkpoints.length < 3) return false;
        
        // Check if response times are consistently increasing
        let increasingTrend = 0;
        
        for (let i = 1; i < checkpoints.length; i++) {
            if (checkpoints[i].metrics.avgResponseTime > checkpoints[i - 1].metrics.avgResponseTime) {
                increasingTrend++;
            }
        }
        
        return increasingTrend > checkpoints.length * 0.7; // 70% increasing trend
    }
    
    /**
     * Detect performance degradation
     */
    detectPerformanceDegradation(checkpoints) {
        if (checkpoints.length < 2) return false;
        
        const first = checkpoints[0].metrics.avgResponseTime;
        const last = checkpoints[checkpoints.length - 1].metrics.avgResponseTime;
        
        // Check if performance degraded by more than 50%
        return last > first * 1.5;
    }
    
    /**
     * Reset metrics
     */
    resetMetrics() {
        this.metrics = {
            requestCount: 0,
            successCount: 0,
            errorCount: 0,
            avgResponseTime: 0,
            minResponseTime: Infinity,
            maxResponseTime: 0,
            percentiles: {},
            throughput: 0
        };
        this.responseTimes = [];
    }
    
    /**
     * Sleep helper
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    
    /**
     * Run comprehensive performance test suite
     */
    async runComprehensiveSuite() {
        const results = {
            latency: {},
            load: {},
            stress: {},
            spike: {},
            endurance: {}
        };
        
        const criticalEndpoints = [
            '/api/v1/oauth/authorize',
            '/api/v1/oauth/token',
            '/oidc/userinfo',
            '/health'
        ];
        
        for (const endpoint of criticalEndpoints) {
            this.tester.addLog(`Testing endpoint: ${endpoint}`, 'info');
            
            // Latency test
            results.latency[endpoint] = await this.latencyTest(endpoint, {
                requests: 50,
                concurrent: 1
            });
            
            // Load test
            results.load[endpoint] = await this.loadTest(endpoint, {
                concurrent: 10,
                duration: 15000
            });
            
            // Stress test (shorter for demo)
            results.stress[endpoint] = await this.stressTest(endpoint, {
                startConcurrent: 5,
                maxConcurrent: 30,
                step: 5,
                duration: 5000
            });
        }
        
        return results;
    }
}

// Export for use
window.PerformanceTester = PerformanceTester;