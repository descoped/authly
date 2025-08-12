/**
 * Authly Comprehensive Testing Toolkit
 * Professional, focused implementation with proper error handling
 */

class ComplianceTester {
    constructor() {
        this.config = {
            serverUrl: 'http://localhost:8000',
            clientId: '',  // No default client - will be created via API
            clientSecret: '',
            redirectUri: `http://${window.location.hostname}:${window.location.port || '8080'}/callback`,
            scopes: 'openid profile email',
            testUsername: 'testuser',
            testPassword: 'TestPassword123!',
            adminClientId: '',  // Not used anymore
            adminClientSecret: ''  // Not used anymore
        };
        
        this.currentTestSuite = null;
        this.testResults = [];
        this.isRunning = false;
        this.isPaused = false;
        this.totalTests = 0;
        this.completedTests = 0;
        this.initComplete = false;  // Track initialization status
        
        // Initialize modules
        this.apiDiscovery = new APIDiscovery();
        this.adminTester = null;
        this.performanceTester = null;
        this.dynamicSuites = [];
        
        // Initialize enhanced logger
        this.logger = new Logger(document.getElementById('executionLog'));
        this.logger.configure({
            logLevel: 'info',
            showSuccesses: false,
            maxHttpBodyLength: 200,
            maxHttpHeadersCount: 3
        });
        
        this.init();
    }
    
    async init() {
        this.loadConfig();
        this.attachEventListeners();
        this.handleCallbackIfPresent();
        
        // Initialize admin client
        this.adminClient = new AdminClient(this.config, this);
        
        // Try to load test client from bootstrap
        const testClient = await this.adminClient.loadTestClient();
        if (testClient && testClient.client_id) {
            this.config.clientId = testClient.client_id;
            this.config.clientSecret = ''; // Public client has no secret
            this.updateConfigUI();
            this.addLog(`Loaded test client: ${testClient.client_id}`, 'success');
        } else if (!this.config.clientId) {
            this.addLog('No OAuth client configured yet', 'info');
            this.addLog('Click the "Client Info" button to create one via API', 'info');
        }
        
        await this.loadDiscovery();
        
        // Mark initialization as complete
        this.initComplete = true;
    }
    
    /**
     * Show current client info and optionally create new client via API
     */
    async createNewClient() {
        this.showExecutionPanel();
        
        // Show current client info
        await this.adminClient.showClientInfo();
        
        
        this.showNotification('Client info displayed in logs', 'info');
    }
    
    loadConfig() {
        // Check localStorage for saved config
        const savedConfig = localStorage.getItem('authly_compliance_config');
        if (savedConfig) {
            const parsed = JSON.parse(savedConfig);
            // Only use saved config if it has a VALID client ID
            // Clear empty or invalid client IDs
            if (parsed.clientId && parsed.clientId !== 'test_client' && parsed.clientId !== '') {
                this.config = { ...this.config, ...parsed };
            } else {
                // Clear invalid config
                localStorage.removeItem('authly_compliance_config');
            }
        }
        
        // No logging about auto-configured clients - we create them via API
        this.updateConfigUI();
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
        
        // Wait for initialization to complete
        if (!this.initComplete) {
            this.addLog('Waiting for initialization to complete...', 'info');
            // Wait up to 5 seconds for init
            for (let i = 0; i < 50; i++) {
                await new Promise(resolve => setTimeout(resolve, 100));
                if (this.initComplete) break;
            }
            if (!this.initComplete) {
                this.showNotification('Initialization timeout. Please refresh the page.', 'error');
                return;
            }
        }
        
        // Ensure client is loaded before running tests
        if (!this.config.clientId) {
            this.addLog('Loading test client before running tests...', 'info');
            const testClient = await this.adminClient.loadTestClient();
            if (testClient && testClient.client_id) {
                this.config.clientId = testClient.client_id;
                this.config.clientSecret = ''; // Public client has no secret
                this.updateConfigUI();
                this.addLog(`Test client loaded: ${testClient.client_id}`, 'success');
            } else {
                this.showNotification('No test client available. Please create one first.', 'error');
                return;
            }
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
        this.addLog(`  Description: ${test.description || 'No description'}`, 'debug');
        
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
        const originalAddLog = this.addLog.bind(this);
        
        // Override addLog to capture test-specific logs
        this.addLog = (message, type = 'info') => {
            originalAddLog(message, type);
            result.debug.logs.push({ message, type, timestamp: new Date().toISOString() });
        };
        
        this.makeRequest = async (url, options = {}) => {
            const fullUrl = this.getFullUrl(url);
            const debugEntry = {
                timestamp: new Date().toISOString(),
                url: url,
                fullUrl: fullUrl,
                method: options.method || 'GET',
                headers: options.headers || {},
                body: options.body || null
            };
            
            result.debug.requests.push(debugEntry);
            
            // Log request details
            this.addLog(`  → ${debugEntry.method} ${url}`, 'debug');
            if (Object.keys(debugEntry.headers).length > 0) {
                this.addLog(`    Headers: ${JSON.stringify(debugEntry.headers)}`, 'debug');
            }
            if (debugEntry.body) {
                const bodyPreview = typeof debugEntry.body === 'string' 
                    ? debugEntry.body.substring(0, 200) 
                    : JSON.stringify(debugEntry.body).substring(0, 200);
                this.addLog(`    Body: ${bodyPreview}${bodyPreview.length >= 200 ? '...' : ''}`, 'debug');
            }
            
            const response = await originalMakeRequest(url, options);
            
            const responseDebug = {
                timestamp: new Date().toISOString(),
                url: url,
                status: response.response?.status || 0,
                statusText: response.response?.statusText || '',
                headers: response.response?.headers ? Object.fromEntries(response.response.headers.entries()) : {},
                data: response.data,
                error: response.error
            };
            
            result.debug.responses.push(responseDebug);
            
            // Log response details
            if (response.error) {
                this.addLog(`  ← Error: ${response.error}`, 'error');
            } else {
                this.addLog(`  ← Status: ${responseDebug.status} ${responseDebug.statusText}`, 
                    responseDebug.status >= 400 ? 'warning' : 'debug');
                
                // Log important headers
                const importantHeaders = ['content-type', 'location', 'x-ratelimit-limit', 'retry-after', 
                                        'access-control-allow-origin', 'set-cookie'];
                const relevantHeaders = {};
                importantHeaders.forEach(header => {
                    if (responseDebug.headers[header]) {
                        relevantHeaders[header] = responseDebug.headers[header];
                    }
                });
                if (Object.keys(relevantHeaders).length > 0) {
                    this.addLog(`    Headers: ${JSON.stringify(relevantHeaders)}`, 'debug');
                }
                
                // Log response data
                if (responseDebug.data) {
                    if (typeof responseDebug.data === 'object') {
                        if (responseDebug.data.error) {
                            this.addLog(`    Error: ${responseDebug.data.error} - ${responseDebug.data.error_description || ''}`, 'warning');
                        } else {
                            const dataPreview = JSON.stringify(responseDebug.data, null, 2).substring(0, 300);
                            this.addLog(`    Data: ${dataPreview}${dataPreview.length >= 300 ? '...' : ''}`, 'debug');
                        }
                    } else {
                        const dataPreview = String(responseDebug.data).substring(0, 200);
                        this.addLog(`    Data: ${dataPreview}${dataPreview.length >= 200 ? '...' : ''}`, 'debug');
                    }
                }
            }
            
            return response;
        };
        
        try {
            const testResult = await test.run(this.config, this);
            
            result.status = testResult.passed ? 'passed' : 'failed';
            result.details = testResult.details || {};
            result.error = testResult.error || null;
            
            // Use enhanced test logging
            const testDuration = Date.now() - testStartTime;
            const testStatus = testResult.passed ? 'passed' : 'failed';
            
            this.logger.logTest(test.name, testStatus, {
                duration: testDuration,
                error: testResult.error,
                details: testResult.details,
                endpoint: test.endpoint,
                suggestion: this.getTestSuggestion(test.name, testResult)
            });
        } catch (error) {
            result.status = 'failed';
            result.error = error.message;
            result.debug.logs.push(`Exception: ${error.stack || error.message}`);
            
            this.logger.logTest(test.name, 'failed', {
                duration: Date.now() - testStartTime,
                error: error.message,
                details: { exception: error.stack },
                endpoint: test.endpoint
            });
        } finally {
            // Restore original methods
            this.makeRequest = originalMakeRequest;
            this.addLog = originalAddLog;
        }
        
        result.duration = Date.now() - startTime;
        this.addTestResult(result);
    }
    
    /**
     * Get full URL for logging
     */
    getFullUrl(url) {
        if (url.startsWith('http')) {
            return url;
        } else if (url.startsWith('/authly-api')) {
            return `${this.config.serverUrl}${url.replace('/authly-api', '')}`;
        } else {
            return `${this.config.serverUrl}${url}`;
        }
    }
    
    completeTestSuite() {
        this.isRunning = false;
        this.updateExecutionStatus('completed');
        this.enableExecutionControls(false);
        this.updateResultsSummary();
        
        const passed = this.testResults.filter(r => r.status === 'passed').length;
        const failed = this.testResults.filter(r => r.status === 'failed').length;
        const total = this.testResults.length;
        
        // Generate comprehensive test summary
        const summary = this.logger.generateTestSummary(this.config);
        this.logger.section('Test Results Summary');
        this.logger.log(summary, 'summary');
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
        // Delegate to enhanced logger
        return this.logger.log(message, type);
    }
    
    /**
     * Get test-specific suggestion for failures
     */
    getTestSuggestion(testName, testResult) {
        const suggestions = {
            'State Parameter Preserved': 'Ensure state parameter is passed through authorization flow',
            'PKCE is Mandatory': 'Add PKCE requirement validation to authorization endpoint',
            'Only S256 Method Allowed': 'Reject plain PKCE method, only allow S256',
            'Rate Limiting': 'Implement rate limiting middleware with appropriate limits',
            'CSRF Protection': 'Add CSRF token validation to login forms'
        };
        
        return suggestions[testName] || 'Check OAuth 2.1 compliance requirements';
    }
    
    /**
     * Generate enhanced test summary using logger
     */
    generateTestSummary() {
        return this.logger.generateTestSummary(this.config);
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
        report += `Client ID: ${this.config.clientId}\n`;
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
                report += ` (${test.duration}ms)\n`;
            });
        });
        
        // Add comprehensive debug section for ALL tests
        report += `\n${'='.repeat(50)}\n`;
        report += `🔍 Complete HTTP Transaction Log:\n`;
        report += `${'='.repeat(50)}\n\n`;
        
        this.testResults.forEach(test => {
            report += `\n━━━ Test: ${test.name} [${test.status.toUpperCase()}] ━━━\n`;
            
            if (test.debug?.requests?.length > 0) {
                test.debug.requests.forEach((req, i) => {
                    const res = test.debug.responses?.[i];
                    
                    report += `\n▶ Request #${i+1}:\n`;
                    report += `  Method: ${req.method}\n`;
                    report += `  URL: ${req.fullUrl || req.url}\n`;
                    
                    if (req.headers && Object.keys(req.headers).length > 0) {
                        report += `  Headers:\n`;
                        Object.entries(req.headers).forEach(([key, value]) => {
                            report += `    ${key}: ${value}\n`;
                        });
                    }
                    
                    if (req.body) {
                        report += `  Body: ${typeof req.body === 'string' ? req.body : JSON.stringify(req.body, null, 2)}\n`;
                    }
                    
                    if (res) {
                        report += `\n◀ Response #${i+1}:\n`;
                        report += `  Status: ${res.status} ${res.statusText || ''}\n`;
                        
                        if (res.headers && Object.keys(res.headers).length > 0) {
                            report += `  Headers:\n`;
                            Object.entries(res.headers).forEach(([key, value]) => {
                                report += `    ${key}: ${value}\n`;
                            });
                        }
                        
                        if (res.data) {
                            report += `  Body:\n`;
                            if (typeof res.data === 'object') {
                                report += `    ${JSON.stringify(res.data, null, 2).split('\n').join('\n    ')}\n`;
                            } else {
                                report += `    ${String(res.data).split('\n').join('\n    ')}\n`;
                            }
                        }
                        
                        if (res.error) {
                            report += `  Error: ${res.error}\n`;
                        }
                    }
                });
            }
            
            if (test.error) {
                report += `\n⚠️ Test Error: ${test.error}\n`;
            }
            
            if (test.details && Object.keys(test.details).length > 0) {
                report += `\nTest Details:\n`;
                report += `${JSON.stringify(test.details, null, 2).split('\n').join('\n  ')}\n`;
            }
        });
        
        // Add execution log at the end
        const logContainer = document.getElementById('executionLog');
        if (logContainer && logContainer.textContent.trim()) {
            report += `\n${'='.repeat(50)}\n`;
            report += `📝 Full Execution Log:\n`;
            report += `${'='.repeat(50)}\n\n`;
            
            const logEntries = Array.from(logContainer.querySelectorAll('.log-entry'))
                .map(entry => entry.textContent)
                .join('\n');
            report += logEntries;
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
        if (url.startsWith('http://') || url.startsWith('https://')) {
            // Absolute URL - don't use it directly, extract path
            try {
                const urlObj = new URL(url);
                const path = urlObj.pathname + urlObj.search;
                // Now treat it as a relative path
                url = path;
            } catch (e) {
                // If URL parsing fails, use as-is
                fullUrl = url;
            }
        }
        
        if (!fullUrl) {
            if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
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
    // Clear bad localStorage data on startup
    const savedConfig = localStorage.getItem('authly_compliance_config');
    if (savedConfig) {
        const parsed = JSON.parse(savedConfig);
        if (parsed.clientId === 'test_client') {
            console.log('Clearing invalid test_client from localStorage');
            localStorage.removeItem('authly_compliance_config');
        }
    }
    
    window.complianceTester = new ComplianceTester();
});