/**
 * Authly Comprehensive Testing Toolkit
 * Professional, focused implementation with proper error handling
 */

class ComplianceTester {
    constructor() {
        this.config = {
            serverUrl: 'http://localhost:8000',
            clientId: 'test_client',
            clientSecret: 'test_secret',
            redirectUri: `http://${window.location.hostname}:${window.location.port || '8080'}/callback`,
            scopes: 'openid profile email',
            testUsername: 'testuser',
            testPassword: 'TestPassword123!',
            adminClientId: 'admin_client',
            adminClientSecret: 'admin_secret'
        };
        
        this.currentTestSuite = null;
        this.testResults = [];
        this.isRunning = false;
        this.isPaused = false;
        this.totalTests = 0;
        this.completedTests = 0;
        
        // Initialize modules
        this.apiDiscovery = new APIDiscovery();
        this.adminTester = null;
        this.performanceTester = null;
        this.dynamicSuites = [];
        
        this.init();
    }
    
    async init() {
        this.loadConfig();
        this.attachEventListeners();
        this.handleCallbackIfPresent();
        await this.loadDiscovery();
    }
    
    loadConfig() {
        const savedConfig = localStorage.getItem('authly_compliance_config');
        if (savedConfig) {
            this.config = { ...this.config, ...JSON.parse(savedConfig) };
            this.updateConfigUI();
        }
    }
    
    saveConfig() {
        this.config.serverUrl = document.getElementById('serverUrl').value;
        this.config.clientId = document.getElementById('clientId').value;
        this.config.clientSecret = document.getElementById('clientSecret').value;
        this.config.redirectUri = document.getElementById('redirectUri').value;
        this.config.scopes = document.getElementById('scopes').value;
        this.config.testUsername = document.getElementById('testUsername').value;
        this.config.testPassword = document.getElementById('testPassword').value;
        
        localStorage.setItem('authly_compliance_config', JSON.stringify(this.config));
        this.showNotification('Configuration saved', 'success');
    }
    
    updateConfigUI() {
        document.getElementById('serverUrl').value = this.config.serverUrl;
        document.getElementById('clientId').value = this.config.clientId;
        document.getElementById('clientSecret').value = this.config.clientSecret;
        document.getElementById('redirectUri').value = this.config.redirectUri;
        document.getElementById('scopes').value = this.config.scopes;
        document.getElementById('testUsername').value = this.config.testUsername;
        document.getElementById('testPassword').value = this.config.testPassword;
    }
    
    attachEventListeners() {
        // Configuration
        document.getElementById('saveConfig')?.addEventListener('click', () => this.saveConfig());
        
        // Test suite buttons
        document.querySelectorAll('.run-suite').forEach(button => {
            button.addEventListener('click', (e) => {
                const suite = e.target.getAttribute('data-suite');
                this.runSingleTestSuite(suite);
            });
        });
        
        // Run all tests - FIXED to clear results and run properly
        document.getElementById('runAllTests')?.addEventListener('click', () => {
            this.runAllTestSuites();
        });
        
        // Custom test
        document.getElementById('runCustomTest')?.addEventListener('click', () => {
            this.showCustomTestDialog();
        });
        
        // Performance tests
        document.getElementById('runPerformanceTests')?.addEventListener('click', () => {
            this.runPerformanceTests();
        });
        
        // Admin tests
        document.getElementById('runAdminTests')?.addEventListener('click', () => {
            this.runAdminTests();
        });
        
        // Dynamic tests
        document.getElementById('runDynamicTests')?.addEventListener('click', () => {
            this.runDynamicTests();
        });
        
        // Refresh discovery
        document.getElementById('refreshDiscovery')?.addEventListener('click', () => {
            this.loadDiscovery();
        });
        
        // Execution controls
        document.getElementById('pauseExecution')?.addEventListener('click', () => {
            this.togglePause();
        });
        
        document.getElementById('stopExecution')?.addEventListener('click', () => {
            this.stopExecution();
        });
        
        // Results actions
        document.getElementById('clearResults')?.addEventListener('click', () => {
            this.clearResults();
        });
        
        document.getElementById('exportReport')?.addEventListener('click', () => {
            this.exportReport();
        });
        
        document.getElementById('copyResults')?.addEventListener('click', () => {
            this.copyToClipboard();
        });
        
        document.getElementById('copyResultsFromPanel')?.addEventListener('click', () => {
            this.copyToClipboard();
        });
    }
    
    handleCallbackIfPresent() {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const error = urlParams.get('error');
        
        if (code || error) {
            this.processOAuthCallback(code, state, error);
            // Clean URL
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }
    
    async processOAuthCallback(code, state, error) {
        if (error) {
            this.addLog(`OAuth error: ${error}`, 'error');
            this.showNotification(`OAuth authorization failed: ${error}`, 'error');
            return;
        }
        
        if (!code) {
            this.addLog('No authorization code received', 'error');
            return;
        }
        
        // Verify state
        const savedState = sessionStorage.getItem('oauth_state');
        if (state !== savedState) {
            this.addLog('State mismatch - possible CSRF attack', 'error');
            return;
        }
        
        this.addLog('Authorization code received, exchanging for tokens...', 'info');
        
        try {
            const { response, data } = await OAuthFlows.exchangeCodeForTokens(this.config, this, code);
            
            if (response.ok) {
                // Store tokens
                sessionStorage.setItem('access_token', data.access_token);
                if (data.refresh_token) {
                    sessionStorage.setItem('refresh_token', data.refresh_token);
                }
                if (data.id_token) {
                    sessionStorage.setItem('id_token', data.id_token);
                }
                
                this.addLog('✅ Token exchange successful', 'success');
                this.showNotification('OAuth flow completed successfully!', 'success');
                
            } else {
                this.addLog('Token exchange failed', 'error');
                this.showNotification(`Token exchange failed: ${data.error || 'Unknown error'}`, 'error');
            }
        } catch (error) {
            this.addLog(`Token exchange error: ${error.message}`, 'error');
            this.showNotification('Token exchange failed', 'error');
        }
    }
    
    /**
     * Run a single test suite
     */
    async runSingleTestSuite(suiteId) {
        if (this.isRunning) {
            this.showNotification('Tests are already running', 'warning');
            return;
        }
        
        // Clear previous results
        this.clearResults();
        
        const suite = TestSuites.getSuite(suiteId);
        if (!suite) {
            this.addLog(`Test suite not found: ${suiteId}`, 'error');
            return;
        }
        
        this.isRunning = true;
        this.isPaused = false;
        this.currentTestSuite = suite;
        this.totalTests = suite.tests.length;
        this.completedTests = 0;
        
        this.updateExecutionStatus('running');
        this.enableExecutionControls(true);
        
        this.addLog(`Starting test suite: ${suite.name}`, 'info');
        this.updateProgress(0, this.totalTests);
        
        // Run tests
        for (const test of suite.tests) {
            if (!this.isRunning) break;
            
            while (this.isPaused) {
                await this.sleep(100);
            }
            
            await this.runTest(test);
            this.completedTests++;
            this.updateProgress(this.completedTests, this.totalTests);
        }
        
        this.completeTestSuite();
    }
    
    /**
     * Run all test suites - FIXED VERSION
     */
    async runAllTestSuites() {
        if (this.isRunning) {
            this.showNotification('Tests are already running', 'warning');
            return;
        }
        
        // Clear ALL previous results
        this.clearResults();
        
        const suiteIds = ['oauth21', 'oidc', 'session', 'security'];
        
        // Calculate total tests
        this.totalTests = 0;
        for (const suiteId of suiteIds) {
            const suite = TestSuites.getSuite(suiteId);
            if (suite) {
                this.totalTests += suite.tests.length;
            }
        }
        
        this.isRunning = true;
        this.isPaused = false;
        this.completedTests = 0;
        
        this.updateExecutionStatus('running');
        this.enableExecutionControls(true);
        this.updateProgress(0, this.totalTests);
        
        // Run each suite
        for (const suiteId of suiteIds) {
            if (!this.isRunning) break;
            
            const suite = TestSuites.getSuite(suiteId);
            if (!suite) continue;
            
            this.currentTestSuite = suite;
            this.addLog(`Starting test suite: ${suite.name}`, 'info');
            
            for (const test of suite.tests) {
                if (!this.isRunning) break;
                
                while (this.isPaused) {
                    await this.sleep(100);
                }
                
                await this.runTest(test);
                this.completedTests++;
                this.updateProgress(this.completedTests, this.totalTests);
            }
        }
        
        this.completeTestSuite();
    }
    
    /**
     * Run a single test
     */
    async runTest(test) {
        this.addLog(`Running: ${test.name}`, 'info');
        
        const startTime = Date.now();
        const result = {
            name: test.name,
            suite: this.currentTestSuite.name,
            timestamp: new Date().toISOString(),
            duration: 0,
            status: 'pending',
            details: {},
            error: null,
            debug: {
                requests: [],
                responses: [],
                logs: []
            }
        };
        
        // Capture debug info during test execution
        const originalMakeRequest = this.makeRequest.bind(this);
        this.makeRequest = async (url, options = {}) => {
            const debugEntry = {
                timestamp: new Date().toISOString(),
                url: url,
                method: options.method || 'GET',
                headers: options.headers || {},
                body: options.body || null
            };
            
            result.debug.requests.push(debugEntry);
            
            const response = await originalMakeRequest(url, options);
            
            result.debug.responses.push({
                timestamp: new Date().toISOString(),
                url: url,
                status: response.response?.status || 0,
                headers: response.response?.headers ? Object.fromEntries(response.response.headers.entries()) : {},
                data: response.data,
                error: response.error
            });
            
            return response;
        };
        
        try {
            const testResult = await test.run(this.config, this);
            
            result.status = testResult.passed ? 'passed' : 'failed';
            result.details = testResult.details || {};
            result.error = testResult.error || null;
            
            if (testResult.passed) {
                this.addLog(`✅ ${test.name}`, 'success');
            } else {
                this.addLog(`❌ ${test.name}: ${testResult.error}`, 'error');
            }
        } catch (error) {
            result.status = 'failed';
            result.error = error.message;
            result.debug.logs.push(`Exception: ${error.stack || error.message}`);
            this.addLog(`❌ ${test.name}: ${error.message}`, 'error');
        } finally {
            // Restore original makeRequest
            this.makeRequest = originalMakeRequest;
        }
        
        result.duration = Date.now() - startTime;
        this.addTestResult(result);
    }
    
    completeTestSuite() {
        this.isRunning = false;
        this.updateExecutionStatus('completed');
        this.enableExecutionControls(false);
        this.updateResultsSummary();
        
        const passed = this.testResults.filter(r => r.status === 'passed').length;
        const failed = this.testResults.filter(r => r.status === 'failed').length;
        const total = this.testResults.length;
        
        this.addLog(`Test suite completed: ${passed}/${total} passed`, 
            failed === 0 ? 'success' : 'warning');
    }
    
    addTestResult(result) {
        this.testResults.push(result);
        this.displayTestResult(result);
    }
    
    displayTestResult(result) {
        const resultsContainer = document.getElementById('resultsDetails');
        
        const resultElement = document.createElement('div');
        resultElement.className = `result-item ${result.status}`;
        
        // Create expandable details section
        const detailsId = `details-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        // Format debug info for display
        const debugInfo = result.debug ? {
            requests: result.debug.requests || [],
            responses: result.debug.responses || [],
            details: result.details || {},
            logs: result.debug.logs || []
        } : result.details;
        
        // Create tabs for better organization
        const tabsHtml = result.debug ? `
            <div class="debug-tabs">
                <button class="debug-tab active" onclick="complianceTester.switchTab('${detailsId}', 'summary')">Summary</button>
                <button class="debug-tab" onclick="complianceTester.switchTab('${detailsId}', 'requests')">Requests (${result.debug.requests?.length || 0})</button>
                <button class="debug-tab" onclick="complianceTester.switchTab('${detailsId}', 'responses')">Responses</button>
                <button class="debug-tab" onclick="complianceTester.switchTab('${detailsId}', 'full')">Full Debug</button>
            </div>
            <div class="debug-content">
                <div id="${detailsId}-summary" class="debug-panel active">
                    <pre>${JSON.stringify(result.details, null, 2)}</pre>
                </div>
                <div id="${detailsId}-requests" class="debug-panel" style="display: none;">
                    <pre>${JSON.stringify(result.debug.requests, null, 2)}</pre>
                </div>
                <div id="${detailsId}-responses" class="debug-panel" style="display: none;">
                    <pre>${JSON.stringify(result.debug.responses, null, 2)}</pre>
                </div>
                <div id="${detailsId}-full" class="debug-panel" style="display: none;">
                    <pre>${JSON.stringify(debugInfo, null, 2)}</pre>
                </div>
            </div>
        ` : `<pre>${JSON.stringify(result.details, null, 2)}</pre>`;
        
        resultElement.innerHTML = `
            <div class="result-header" onclick="complianceTester.toggleDetails('${detailsId}')">
                <span class="result-name">${result.name}</span>
                <span class="result-status ${result.status}">${result.status}</span>
                <span class="expand-icon" id="icon-${detailsId}">▶</span>
            </div>
            ${result.error ? `<div class="result-error">${result.error}</div>` : ''}
            <div class="result-meta">Duration: ${result.duration}ms | Suite: ${result.suite}</div>
            <div class="result-details-json" id="${detailsId}" style="display: none;">
                ${tabsHtml}
            </div>
        `;
        
        resultsContainer.appendChild(resultElement);
    }
    
    switchTab(detailsId, tabName) {
        // Hide all panels
        const panels = document.querySelectorAll(`#${detailsId}-summary, #${detailsId}-requests, #${detailsId}-responses, #${detailsId}-full`);
        panels.forEach(panel => {
            if (panel) panel.style.display = 'none';
        });
        
        // Show selected panel
        const selectedPanel = document.getElementById(`${detailsId}-${tabName}`);
        if (selectedPanel) selectedPanel.style.display = 'block';
        
        // Update active tab
        const tabs = document.querySelectorAll(`[onclick*="${detailsId}"].debug-tab`);
        tabs.forEach(tab => tab.classList.remove('active'));
        event.target.classList.add('active');
    }
    
    toggleDetails(detailsId) {
        const details = document.getElementById(detailsId);
        const icon = document.getElementById(`icon-${detailsId}`);
        if (details.style.display === 'none') {
            details.style.display = 'block';
            icon.textContent = '▼';
        } else {
            details.style.display = 'none';
            icon.textContent = '▶';
        }
    }
    
    toggleExecutionPanel() {
        const panel = document.getElementById('executionPanel');
        if (panel.classList.contains('active')) {
            panel.classList.remove('active');
        } else {
            panel.classList.add('active');
        }
    }
    
    showExecutionPanel() {
        const panel = document.getElementById('executionPanel');
        panel.classList.add('active');
    }
    
    clearResults() {
        this.testResults = [];
        document.getElementById('resultsDetails').innerHTML = '';
        this.updateResultsSummary();
        document.getElementById('executionLog').innerHTML = '';
    }
    
    updateResultsSummary() {
        const passed = this.testResults.filter(r => r.status === 'passed').length;
        const failed = this.testResults.filter(r => r.status === 'failed').length;
        const skipped = this.testResults.filter(r => r.status === 'skipped').length;
        const total = this.testResults.length;
        
        document.getElementById('passedCount').textContent = passed;
        document.getElementById('failedCount').textContent = failed;
        document.getElementById('skippedCount').textContent = skipped;
        document.getElementById('totalCount').textContent = total;
        
        // Enable/disable copy button
        const copyButton = document.getElementById('copyResultsFromPanel');
        if (copyButton) {
            copyButton.disabled = total === 0;
        }
    }
    
    updateExecutionStatus(status) {
        const statusElement = document.getElementById('executionStatus');
        statusElement.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        statusElement.className = `execution-status ${status}`;
        
        // Show execution panel but don't auto-hide it
        const panel = document.getElementById('executionPanel');
        if (panel) {
            if (status === 'running') {
                panel.classList.add('active');
            }
            // Don't auto-hide - let user close it manually
        }
    }
    
    updateProgress(completed, total) {
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        
        const percentage = total > 0 ? (completed / total) * 100 : 0;
        progressFill.style.width = `${percentage}%`;
        progressText.textContent = `${completed} / ${total} tests`;
    }
    
    enableExecutionControls(enable) {
        document.getElementById('pauseExecution').disabled = !enable;
        document.getElementById('stopExecution').disabled = !enable;
    }
    
    togglePause() {
        this.isPaused = !this.isPaused;
        const button = document.getElementById('pauseExecution');
        button.textContent = this.isPaused ? 'Resume' : 'Pause';
        this.addLog(this.isPaused ? 'Execution paused' : 'Execution resumed', 'info');
    }
    
    stopExecution() {
        this.isRunning = false;
        this.isPaused = false;
        this.updateExecutionStatus('stopped');
        this.enableExecutionControls(false);
        this.addLog('Execution stopped by user', 'warning');
    }
    
    addLog(message, type = 'info') {
        const logContainer = document.getElementById('executionLog');
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${type}`;
        logEntry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        logContainer.appendChild(logEntry);
        logContainer.scrollTop = logContainer.scrollHeight;
    }
    
    showNotification(message, type = 'info') {
        // Simple notification - could be enhanced with a toast library
        console.log(`[${type.toUpperCase()}] ${message}`);
        this.addLog(message, type);
    }
    
    async copyToClipboard() {
        if (this.testResults.length === 0) {
            this.showNotification('No results to copy', 'warning');
            return;
        }
        
        const report = this.generateShareableReport();
        
        try {
            await navigator.clipboard.writeText(report);
            this.showNotification('✅ Results copied to clipboard!', 'success');
        } catch (err) {
            // Fallback
            const textArea = document.createElement('textarea');
            textArea.value = report;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            document.body.appendChild(textArea);
            textArea.select();
            
            try {
                document.execCommand('copy');
                this.showNotification('✅ Results copied to clipboard!', 'success');
            } catch (err2) {
                this.showNotification('Failed to copy to clipboard', 'error');
            }
            
            document.body.removeChild(textArea);
        }
    }
    
    async copyExecutionLog() {
        const logContainer = document.getElementById('executionLog');
        if (!logContainer || !logContainer.textContent.trim()) {
            this.showNotification('No logs to copy', 'warning');
            return;
        }
        
        // Get all log entries
        const logEntries = Array.from(logContainer.querySelectorAll('.log-entry'))
            .map(entry => entry.textContent)
            .join('\n');
        
        const logReport = `🔐 Authly Compliance Tester - Execution Log\n` +
            `${'='.repeat(50)}\n` +
            `Timestamp: ${new Date().toISOString()}\n` +
            `Server: ${this.config.serverUrl}\n` +
            `${'='.repeat(50)}\n\n` +
            logEntries;
        
        try {
            await navigator.clipboard.writeText(logReport);
            this.showNotification('✅ Execution log copied to clipboard!', 'success');
        } catch (err) {
            // Fallback
            const textArea = document.createElement('textarea');
            textArea.value = logReport;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            document.body.appendChild(textArea);
            textArea.select();
            
            try {
                document.execCommand('copy');
                this.showNotification('✅ Execution log copied to clipboard!', 'success');
            } catch (err2) {
                this.showNotification('Failed to copy log to clipboard', 'error');
            }
            
            document.body.removeChild(textArea);
        }
    }
    
    generateShareableReport() {
        const summary = {
            total: this.testResults.length,
            passed: this.testResults.filter(r => r.status === 'passed').length,
            failed: this.testResults.filter(r => r.status === 'failed').length,
            skipped: this.testResults.filter(r => r.status === 'skipped').length
        };
        
        const passRate = summary.total > 0 ? ((summary.passed / summary.total) * 100).toFixed(1) : '0';
        
        let report = `🔐 Authly Compliance Test Results\n`;
        report += `${'='.repeat(50)}\n`;
        report += `Timestamp: ${new Date().toISOString()}\n`;
        report += `Server: ${this.config.serverUrl}\n`;
        report += `${'='.repeat(50)}\n\n`;
        
        report += `📊 Test Summary:\n`;
        report += `• Total Tests: ${summary.total}\n`;
        report += `• Passed: ${summary.passed} ✅\n`;
        report += `• Failed: ${summary.failed} ❌\n`;
        report += `• Pass Rate: ${passRate}%\n\n`;
        
        // Group by suite
        const suiteResults = {};
        this.testResults.forEach(result => {
            if (!suiteResults[result.suite]) {
                suiteResults[result.suite] = [];
            }
            suiteResults[result.suite].push(result);
        });
        
        report += `📋 Detailed Results:\n`;
        Object.entries(suiteResults).forEach(([suiteName, tests]) => {
            report += `\n${suiteName}:\n`;
            tests.forEach(test => {
                const icon = test.status === 'passed' ? '✅' : '❌';
                report += `  ${icon} ${test.name}`;
                if (test.error) {
                    report += ` - ${test.error}`;
                }
                report += ` (${test.duration}ms)`;
                report += `\n`;
                
                // Add debug info for failed tests
                if (test.status === 'failed' && test.debug) {
                    report += `     Debug Info:\n`;
                    if (test.debug.requests?.length > 0) {
                        const lastRequest = test.debug.requests[test.debug.requests.length - 1];
                        report += `     → Last Request: ${lastRequest.method} ${lastRequest.url}\n`;
                    }
                    if (test.debug.responses?.length > 0) {
                        const lastResponse = test.debug.responses[test.debug.responses.length - 1];
                        report += `     ← Last Response: Status ${lastResponse.status}\n`;
                        if (lastResponse.error) {
                            report += `     ⚠️ Error: ${lastResponse.error}\n`;
                        }
                    }
                }
            });
        });
        
        // Add failed test debug details section
        const failedTests = this.testResults.filter(r => r.status === 'failed');
        if (failedTests.length > 0) {
            report += `\n${'='.repeat(50)}\n`;
            report += `🔍 Debug Information for Failed Tests:\n\n`;
            
            failedTests.forEach(test => {
                report += `Test: ${test.name}\n`;
                report += `Error: ${test.error || 'Unknown'}\n`;
                
                if (test.debug?.requests?.length > 0) {
                    report += `Requests made:\n`;
                    test.debug.requests.forEach((req, i) => {
                        report += `  ${i+1}. ${req.method} ${req.url}\n`;
                    });
                }
                
                if (test.debug?.responses?.length > 0) {
                    report += `Responses received:\n`;
                    test.debug.responses.forEach((res, i) => {
                        report += `  ${i+1}. Status ${res.status} from ${res.url}\n`;
                        if (res.data && typeof res.data === 'object') {
                            report += `     Data: ${JSON.stringify(res.data).substring(0, 100)}...\n`;
                        }
                    });
                }
                report += `\n`;
            });
        }
        
        return report;
    }
    
    exportReport() {
        const report = {
            timestamp: new Date().toISOString(),
            config: this.config,
            results: this.testResults,
            summary: {
                total: this.testResults.length,
                passed: this.testResults.filter(r => r.status === 'passed').length,
                failed: this.testResults.filter(r => r.status === 'failed').length,
                skipped: this.testResults.filter(r => r.status === 'skipped').length
            }
        };
        
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `authly-test-report-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        
        this.showNotification('Report exported', 'success');
    }
    
    showCustomTestDialog() {
        // Implementation for custom test dialog
        this.showNotification('Custom test dialog - implement as needed', 'info');
    }
    
    /**
     * Make API request with proper error handling
     */
    async makeRequest(url, options = {}) {
        // Use proxy for API calls when running in browser to avoid CORS
        let fullUrl;
        if (url.startsWith('http')) {
            fullUrl = url;
        } else if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
            // Route through appropriate proxy based on path
            if (url.startsWith('/api/v1/')) {
                // Use authly-api proxy for /api/v1 paths
                fullUrl = `/authly-api${url}`;
            } else if (url.startsWith('/.well-known/') || url.startsWith('/auth/') || 
                       url.startsWith('/oidc/') || url.startsWith('/api/')) {
                // These are already proxied by nginx
                fullUrl = url;
            } else {
                // Default to authly-api proxy
                fullUrl = `/authly-api${url}`;
            }
        } else {
            fullUrl = `${this.config.serverUrl}${url}`;
        }
        
        try {
            const response = await fetch(fullUrl, {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                // Don't follow redirects for OAuth authorize endpoint
                redirect: options.redirect || 'follow'
            });
            
            const contentType = response.headers.get('content-type');
            let data = null;
            
            // Only try to parse response if there's content
            if (response.status !== 204 && contentType) {
                data = contentType.includes('application/json')
                    ? await response.json()
                    : await response.text();
            }
            
            return { response, data };
        } catch (error) {
            // Network error - return proper error structure
            return {
                response: { 
                    ok: false, 
                    status: 0,
                    headers: new Headers()
                },
                data: null,
                error: error.message
            };
        }
    }
    
    generateRandomString(length) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        let result = '';
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        for (let i = 0; i < length; i++) {
            result += chars[array[i] % chars.length];
        }
        return result;
    }
    
    async sha256(plain) {
        const encoder = new TextEncoder();
        const data = encoder.encode(plain);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return btoa(String.fromCharCode(...new Uint8Array(hash)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }
    
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    
    /**
     * Load API discovery
     */
    async loadDiscovery() {
        const statusElement = document.getElementById('discoveryStatus');
        if (!statusElement) return;
        
        try {
            statusElement.textContent = '🔍 Loading API discovery...';
            await this.apiDiscovery.loadOpenAPISpec(this.config.serverUrl);
            await this.apiDiscovery.loadDiscoveryDocument(this.config.serverUrl);
            
            this.dynamicSuites = this.apiDiscovery.generateDynamicTestSuites();
            
            const endpointCount = Object.values(this.apiDiscovery.endpoints)
                .reduce((sum, arr) => sum + arr.length, 0);
            
            statusElement.innerHTML = `✅ Discovered ${endpointCount} endpoints`;
            statusElement.className = 'discovery-success';
            
            this.adminTester = new AdminTester(this.config, this);
            this.performanceTester = new PerformanceTester(this.config, this);
            
        } catch (error) {
            statusElement.innerHTML = `❌ Discovery failed: ${error.message}`;
            statusElement.className = 'discovery-error';
        }
    }
    
    async runPerformanceTests() {
        this.showNotification('Performance tests - implement as needed', 'info');
    }
    
    async runAdminTests() {
        this.showNotification('Admin tests - implement as needed', 'info');
    }
    
    async runDynamicTests() {
        this.showNotification('Dynamic tests - implement as needed', 'info');
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.complianceTester = new ComplianceTester();
});