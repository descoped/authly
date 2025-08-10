/**
 * Authly Compliance Tester
 * Core testing logic and UI interactions
 */

class ComplianceTester {
    constructor() {
        // Check if we're running in a Docker environment or locally
        // When accessed from browser, we need to use localhost
        // The server URL should be what the browser can reach
        const isDocker = window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1';
        
        this.config = {
            serverUrl: isDocker ? `http://${window.location.hostname}:8000` : 'http://localhost:8000',
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
        
        // Load API discovery
        await this.loadDiscovery();
    }
    
    loadConfig() {
        // Load config from localStorage if available
        const savedConfig = localStorage.getItem('authly_compliance_config');
        if (savedConfig) {
            this.config = { ...this.config, ...JSON.parse(savedConfig) };
            this.updateConfigUI();
        }
    }
    
    saveConfig() {
        // Get values from form
        this.config.serverUrl = document.getElementById('serverUrl').value;
        this.config.clientId = document.getElementById('clientId').value;
        this.config.clientSecret = document.getElementById('clientSecret').value;
        this.config.redirectUri = document.getElementById('redirectUri').value;
        this.config.scopes = document.getElementById('scopes').value;
        this.config.testUsername = document.getElementById('testUsername').value;
        this.config.testPassword = document.getElementById('testPassword').value;
        
        // Save to localStorage
        localStorage.setItem('authly_compliance_config', JSON.stringify(this.config));
        
        this.showNotification('Configuration saved successfully', 'success');
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
        document.getElementById('saveConfig').addEventListener('click', () => this.saveConfig());
        
        // Test suite buttons
        document.querySelectorAll('.run-suite').forEach(button => {
            button.addEventListener('click', (e) => {
                const suite = e.target.getAttribute('data-suite');
                this.runTestSuite(suite);
            });
        });
        
        // Run all tests
        document.getElementById('runAllTests').addEventListener('click', () => {
            this.runAllTestSuites();
        });
        
        // Custom test
        document.getElementById('runCustomTest').addEventListener('click', () => {
            this.showCustomTestDialog();
        });
        
        // Performance tests
        document.getElementById('runPerformanceTests').addEventListener('click', () => {
            this.runPerformanceTests();
        });
        
        // Admin tests
        document.getElementById('runAdminTests').addEventListener('click', () => {
            this.runAdminTests();
        });
        
        // Dynamic tests
        document.getElementById('runDynamicTests').addEventListener('click', () => {
            this.runDynamicTests();
        });
        
        // Refresh discovery
        document.getElementById('refreshDiscovery').addEventListener('click', () => {
            this.loadDiscovery();
        });
        
        // Execution controls
        document.getElementById('pauseExecution').addEventListener('click', () => {
            this.togglePause();
        });
        
        document.getElementById('stopExecution').addEventListener('click', () => {
            this.stopExecution();
        });
        
        // Results actions
        document.getElementById('copyResults').addEventListener('click', () => {
            this.copyToClipboard();
        });
        
        document.getElementById('copyResultsFromPanel').addEventListener('click', () => {
            this.copyToClipboard();
        });
        
        document.getElementById('clearResults').addEventListener('click', () => {
            this.clearResults();
        });
        
        document.getElementById('exportReport').addEventListener('click', () => {
            this.exportReport();
        });
    }
    
    handleCallbackIfPresent() {
        // Check if we're handling an OAuth callback
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const error = urlParams.get('error');
        
        if (code || error) {
            // Store callback data
            const callbackData = {
                code,
                state,
                error,
                error_description: urlParams.get('error_description'),
                timestamp: new Date().toISOString()
            };
            
            sessionStorage.setItem('oauth_callback', JSON.stringify(callbackData));
            
            // Clear URL parameters
            window.history.replaceState({}, document.title, window.location.pathname);
            
            // Show callback notification
            if (code) {
                this.addLog('OAuth callback received with authorization code', 'success');
                this.processOAuthCallback();
            } else {
                this.addLog(`OAuth callback error: ${error}`, 'error');
                this.showNotification(`OAuth error: ${error}`, 'error');
            }
        }
    }
    
    async processOAuthCallback() {
        const callbackData = JSON.parse(sessionStorage.getItem('oauth_callback'));
        if (!callbackData || !callbackData.code) {
            return;
        }
        
        this.addLog('Processing OAuth callback and exchanging code for tokens...', 'info');
        
        try {
            // Exchange authorization code for tokens
            const { response, data } = await OAuthFlows.exchangeCodeForTokens(this.config, this, callbackData.code);
            
            if (response.ok && data.access_token) {
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
                
                // Update UI to show we're authenticated
                this.updateAuthenticationStatus(true);
                
                // Test the tokens
                await this.testTokensAfterCallback(data);
                
            } else {
                this.addLog('❌ Token exchange failed', 'error');
                this.showNotification(`Token exchange failed: ${data.error || 'Unknown error'}`, 'error');
            }
        } catch (error) {
            this.addLog(`❌ Token exchange error: ${error.message}`, 'error');
            this.showNotification('Token exchange failed', 'error');
        }
    }
    
    async testTokensAfterCallback(tokenData) {
        this.addLog('Testing received tokens...', 'info');
        
        // Test ID token if present
        if (tokenData.id_token) {
            const idTokenValidation = OIDCFlows.validateIDToken(tokenData.id_token, this.config);
            if (idTokenValidation.valid) {
                this.addLog('✅ ID token validation passed', 'success');
                this.addLog(`  Subject: ${idTokenValidation.payload.sub}`, 'info');
                this.addLog(`  Audience: ${idTokenValidation.payload.aud}`, 'info');
                this.addLog(`  Expires: ${new Date(idTokenValidation.payload.exp * 1000).toISOString()}`, 'info');
            } else {
                this.addLog(`❌ ID token validation failed: ${idTokenValidation.error}`, 'error');
            }
        }
        
        // Test UserInfo endpoint
        if (tokenData.access_token) {
            try {
                const { response, data } = await OIDCFlows.fetchUserInfo(this.config, this, tokenData.access_token);
                if (response.ok) {
                    this.addLog('✅ UserInfo endpoint accessible', 'success');
                    this.addLog(`  User claims: ${Object.keys(data).join(', ')}`, 'info');
                } else {
                    this.addLog('❌ UserInfo endpoint failed', 'error');
                }
            } catch (error) {
                this.addLog(`❌ UserInfo error: ${error.message}`, 'error');
            }
        }
    }
    
    updateAuthenticationStatus(isAuthenticated) {
        // Update UI to show authentication status
        const statusElement = document.createElement('div');
        statusElement.className = isAuthenticated ? 'auth-status authenticated' : 'auth-status unauthenticated';
        statusElement.innerHTML = isAuthenticated ? 
            '🔓 Authenticated with OAuth tokens' : 
            '🔒 Not authenticated';
        
        // Add to header if not already present
        const header = document.querySelector('.header');
        const existingStatus = header.querySelector('.auth-status');
        if (existingStatus) {
            existingStatus.replaceWith(statusElement);
        } else {
            header.appendChild(statusElement);
        }
    }
    
    async startInteractiveOAuthFlow() {
        this.addLog('Starting interactive OAuth 2.1 + OIDC flow...', 'info');
        
        try {
            const flowData = await OAuthFlows.startAuthorizationFlow(this.config, this);
            
            this.addLog('Authorization URL generated:', 'info');
            this.addLog(flowData.authUrl, 'info');
            this.addLog('PKCE challenge created and stored', 'info');
            
            // Show authorization prompt
            const proceed = confirm(
                'This will open a new window for OAuth authorization.\n\n' +
                'You will be redirected to the Authly login page, and after login, ' +
                'redirected back to this compliance tester.\n\n' +
                'Continue?'
            );
            
            if (proceed) {
                // Open authorization URL in same window
                window.location.href = flowData.authUrl;
            } else {
                this.addLog('OAuth flow cancelled by user', 'warning');
            }
        } catch (error) {
            this.addLog(`❌ OAuth flow error: ${error.message}`, 'error');
            this.showNotification('Failed to start OAuth flow', 'error');
        }
    }
    
    async startBrowserSessionFlow() {
        this.addLog('Starting browser session login flow...', 'info');
        
        try {
            // Navigate to login page with redirect back to compliance tester
            const loginUrl = `${this.config.serverUrl}/auth/login?redirect_to=${encodeURIComponent(window.location.origin)}`;
            
            const proceed = confirm(
                'This will navigate to the Authly login page.\n\n' +
                'After logging in, you will be redirected back to the compliance tester ' +
                'with an active browser session.\n\n' +
                'Continue?'
            );
            
            if (proceed) {
                window.location.href = loginUrl;
            } else {
                this.addLog('Session login cancelled by user', 'warning');
            }
        } catch (error) {
            this.addLog(`❌ Session flow error: ${error.message}`, 'error');
            this.showNotification('Failed to start session flow', 'error');
        }
    }
    
    async logout() {
        this.addLog('Logging out...', 'info');
        
        try {
            // Clear stored tokens
            sessionStorage.removeItem('access_token');
            sessionStorage.removeItem('refresh_token');
            sessionStorage.removeItem('id_token');
            sessionStorage.removeItem('oauth_callback');
            sessionStorage.removeItem('oauth_state');
            sessionStorage.removeItem('code_verifier');
            sessionStorage.removeItem('oidc_nonce');
            
            // Call logout endpoint if session-based
            const logoutUrl = `${this.config.serverUrl}/auth/logout?redirect_to=${encodeURIComponent(window.location.origin)}`;
            
            // Navigate to logout URL
            window.location.href = logoutUrl;
            
        } catch (error) {
            this.addLog(`❌ Logout error: ${error.message}`, 'error');
            this.showNotification('Logout failed', 'error');
        }
    }
    
    async runTestSuite(suiteId) {
        if (this.isRunning) {
            this.showNotification('Tests are already running', 'warning');
            return;
        }
        
        this.isRunning = true;
        this.isPaused = false;
        this.updateExecutionStatus('running');
        this.enableExecutionControls(true);
        
        // Get test suite
        const suite = TestSuites.getSuite(suiteId);
        if (!suite) {
            this.addLog(`Test suite not found: ${suiteId}`, 'error');
            this.stopExecution();
            return;
        }
        
        this.currentTestSuite = suite;
        this.totalTests = suite.tests.length;
        this.completedTests = 0;
        
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
    
    async runAllTestSuites() {
        const suiteIds = ['oauth21', 'oidc', 'session', 'security'];
        
        for (const suiteId of suiteIds) {
            await this.runTestSuite(suiteId);
            if (!this.isRunning) break;
        }
    }
    
    async runTest(test) {
        this.addLog(`Running test: ${test.name}`, 'info');
        
        const startTime = Date.now();
        const result = {
            name: test.name,
            suite: this.currentTestSuite.name,
            timestamp: new Date().toISOString(),
            duration: 0,
            status: 'pending',
            details: {},
            error: null
        };
        
        try {
            // Run the test function
            const testResult = await test.run(this.config, this);
            
            result.status = testResult.passed ? 'passed' : 'failed';
            result.details = testResult.details || {};
            
            if (!testResult.passed) {
                result.error = testResult.error || 'Test assertion failed';
                this.addLog(`✗ ${test.name}: ${result.error}`, 'error');
            } else {
                this.addLog(`✓ ${test.name}`, 'success');
            }
            
        } catch (error) {
            result.status = 'failed';
            result.error = error.message;
            this.addLog(`✗ ${test.name}: ${error.message}`, 'error');
        }
        
        result.duration = Date.now() - startTime;
        this.testResults.push(result);
        this.updateResultsDisplay();
    }
    
    completeTestSuite() {
        this.isRunning = false;
        this.updateExecutionStatus('completed');
        this.enableExecutionControls(false);
        
        const passed = this.testResults.filter(r => r.status === 'passed').length;
        const failed = this.testResults.filter(r => r.status === 'failed').length;
        
        this.addLog(`Test suite completed: ${passed} passed, ${failed} failed`, 'info');
        
        if (failed === 0) {
            this.showNotification('All tests passed!', 'success');
        } else {
            this.showNotification(`${failed} test(s) failed`, 'error');
        }
    }
    
    togglePause() {
        this.isPaused = !this.isPaused;
        const button = document.getElementById('pauseExecution');
        button.textContent = this.isPaused ? 'Resume' : 'Pause';
        
        if (this.isPaused) {
            this.addLog('Execution paused', 'warning');
            this.updateExecutionStatus('paused');
        } else {
            this.addLog('Execution resumed', 'info');
            this.updateExecutionStatus('running');
        }
    }
    
    stopExecution() {
        this.isRunning = false;
        this.isPaused = false;
        this.updateExecutionStatus('stopped');
        this.enableExecutionControls(false);
        this.addLog('Execution stopped', 'warning');
    }
    
    clearResults() {
        if (confirm('Are you sure you want to clear all test results?')) {
            this.testResults = [];
            this.updateResultsDisplay();
            document.getElementById('executionLog').innerHTML = '';
            this.addLog('Results cleared', 'info');
            
            // Reset execution status
            this.updateExecutionStatus('idle');
            this.updateProgress(0, 0);
        }
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
        a.download = `authly-compliance-report-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        
        this.showNotification('Report exported successfully', 'success');
    }
    
    async copyToClipboard() {
        if (this.testResults.length === 0) {
            this.showNotification('No results to copy. Run some tests first!', 'warning');
            return;
        }
        
        const report = this.generateShareableReport();
        
        try {
            await navigator.clipboard.writeText(report);
            const summary = {
                total: this.testResults.length,
                passed: this.testResults.filter(r => r.status === 'passed').length,
                failed: this.testResults.filter(r => r.status === 'failed').length
            };
            this.showNotification(
                `📋 ${summary.total} test results copied to clipboard (${summary.passed} passed, ${summary.failed} failed)`, 
                'success'
            );
            this.addLog('Results copied to clipboard - ready to paste!', 'success');
        } catch (err) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = report;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            
            try {
                document.execCommand('copy');
                this.showNotification('Results copied to clipboard (fallback method)', 'success');
                this.addLog('Results copied to clipboard using fallback method', 'success');
            } catch (err2) {
                this.showNotification('Failed to copy to clipboard. Please try manually selecting the results.', 'error');
                this.addLog('Clipboard copy failed - browser may not support this feature', 'error');
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
        report += `${'='.repeat(50)}\n\n`;
        report += `📊 Test Summary:\n`;
        report += `• Total Tests: ${summary.total}\n`;
        report += `• Passed: ${summary.passed} ✅\n`;
        report += `• Failed: ${summary.failed} ${summary.failed > 0 ? '❌' : ''}\n`;
        report += `• Skipped: ${summary.skipped} ⏭️\n`;
        report += `• Pass Rate: ${passRate}%\n\n`;
        
        report += `⚙️ Configuration:\n`;
        report += `• Server: ${this.config.serverUrl}\n`;
        report += `• Client ID: ${this.config.clientId}\n`;
        report += `• Scopes: ${this.config.scopes}\n`;
        report += `• Timestamp: ${new Date().toISOString()}\n\n`;
        
        // Group results by suite
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
                const icon = test.status === 'passed' ? '✅' : 
                           test.status === 'failed' ? '❌' : '⏭️';
                report += `  ${icon} ${test.name}`;
                if (test.error) {
                    report += ` - ${test.error}`;
                }
                report += `\n`;
            });
        });
        
        if (summary.failed > 0) {
            report += `\n⚠️ Failed Tests Details:\n`;
            this.testResults.filter(r => r.status === 'failed').forEach(test => {
                report += `\n❌ ${test.name} (${test.suite}):\n`;
                report += `   Error: ${test.error || 'Test assertion failed'}\n`;
                if (test.details && Object.keys(test.details).length > 0) {
                    report += `   Details: ${JSON.stringify(test.details, null, 2)}\n`;
                }
            });
        }
        
        report += `\n${'='.repeat(50)}\n`;
        report += `Generated by Authly Compliance Tester\n`;
        report += `OAuth 2.1 + PKCE & OpenID Connect 1.0 Validation Suite`;
        
        return report;
    }
    
    showCustomTestDialog() {
        const dialog = document.createElement('div');
        dialog.className = 'custom-test-dialog';
        dialog.innerHTML = `
            <div class="dialog-overlay">
                <div class="dialog-content">
                    <h3>Interactive Flow Testing</h3>
                    <p>Test real OAuth and session flows with interactive login:</p>
                    
                    <div class="dialog-buttons">
                        <button id="testOAuthFlow" class="btn btn-primary">
                            🔐 OAuth 2.1 + OIDC Flow
                        </button>
                        <button id="testSessionFlow" class="btn btn-primary">
                            👤 Browser Session Flow
                        </button>
                        <button id="testLogout" class="btn btn-secondary">
                            🚪 Logout
                        </button>
                        <button id="closeDialog" class="btn btn-secondary">
                            Cancel
                        </button>
                    </div>
                    
                    <div class="dialog-info">
                        <p><strong>OAuth Flow:</strong> Complete authorization code + PKCE + OIDC flow</p>
                        <p><strong>Session Flow:</strong> Browser-based login with session cookies</p>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(dialog);
        
        // Event handlers
        document.getElementById('testOAuthFlow').addEventListener('click', () => {
            this.startInteractiveOAuthFlow();
            document.body.removeChild(dialog);
        });
        
        document.getElementById('testSessionFlow').addEventListener('click', () => {
            this.startBrowserSessionFlow();
            document.body.removeChild(dialog);
        });
        
        document.getElementById('testLogout').addEventListener('click', () => {
            this.logout();
            document.body.removeChild(dialog);
        });
        
        document.getElementById('closeDialog').addEventListener('click', () => {
            document.body.removeChild(dialog);
        });
        
        // Close on overlay click
        dialog.addEventListener('click', (e) => {
            if (e.target === dialog.querySelector('.dialog-overlay')) {
                document.body.removeChild(dialog);
            }
        });
    }
    
    updateExecutionStatus(status) {
        const statusElement = document.getElementById('executionStatus');
        statusElement.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        statusElement.className = `status-value ${status}`;
    }
    
    updateProgress(completed, total) {
        const percentage = total > 0 ? (completed / total) * 100 : 0;
        document.getElementById('progressFill').style.width = `${percentage}%`;
        document.getElementById('progressText').textContent = `${completed} / ${total} tests`;
    }
    
    updateResultsDisplay() {
        const passed = this.testResults.filter(r => r.status === 'passed').length;
        const failed = this.testResults.filter(r => r.status === 'failed').length;
        const skipped = this.testResults.filter(r => r.status === 'skipped').length;
        const total = this.testResults.length;
        
        document.getElementById('passedCount').textContent = passed;
        document.getElementById('failedCount').textContent = failed;
        document.getElementById('skippedCount').textContent = skipped;
        document.getElementById('totalCount').textContent = total;
        
        // Enable/disable copy button based on results
        const copyButton = document.getElementById('copyResultsFromPanel');
        const headerCopyButton = document.getElementById('copyResults');
        
        if (total > 0) {
            copyButton.disabled = false;
            headerCopyButton.disabled = false;
            copyButton.title = 'Copy test results to clipboard';
            headerCopyButton.title = 'Copy test results to clipboard';
        } else {
            copyButton.disabled = true;
            headerCopyButton.disabled = true;
            copyButton.title = 'No results to copy';
            headerCopyButton.title = 'No results to copy';
        }
        
        // Update detailed results
        const resultsContainer = document.getElementById('resultsDetails');
        resultsContainer.innerHTML = '';
        
        this.testResults.forEach(result => {
            const resultItem = document.createElement('div');
            resultItem.className = `result-item ${result.status}`;
            
            resultItem.innerHTML = `
                <div class="result-header">
                    <span class="result-name">${result.name}</span>
                    <span class="result-status ${result.status}">${result.status}</span>
                </div>
                <div class="result-details">
                    Suite: ${result.suite} | Duration: ${result.duration}ms
                </div>
                ${result.error ? `<div class="result-error">${result.error}</div>` : ''}
            `;
            
            resultsContainer.appendChild(resultItem);
        });
    }
    
    enableExecutionControls(enabled) {
        document.getElementById('pauseExecution').disabled = !enabled;
        document.getElementById('stopExecution').disabled = !enabled;
        
        // Disable test buttons while running
        document.querySelectorAll('.run-suite').forEach(button => {
            button.disabled = enabled;
        });
        document.getElementById('runAllTests').disabled = enabled;
    }
    
    addLog(message, level = 'info') {
        const logContainer = document.getElementById('executionLog');
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${level}`;
        
        const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
        logEntry.textContent = `[${timestamp}] ${message}`;
        
        logContainer.appendChild(logEntry);
        logContainer.scrollTop = logContainer.scrollHeight;
    }
    
    showNotification(message, type = 'info') {
        // Simple notification (can be enhanced with a toast library)
        this.addLog(message, type);
    }
    
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    
    // Utility methods for tests
    async makeRequest(url, options = {}) {
        // When running in browser, use proxy to avoid CORS issues
        let fullUrl;
        
        if (url.startsWith('http')) {
            fullUrl = url;
        } else if (url.startsWith('/.well-known')) {
            // Well-known endpoints are proxied directly
            fullUrl = url;
        } else {
            // Use proxy for API calls to avoid CORS
            fullUrl = `/authly-api${url}`;
        }
        
        try {
            const response = await fetch(fullUrl, {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            });
            
            const data = response.headers.get('content-type')?.includes('application/json')
                ? await response.json()
                : await response.text();
            
            return { response, data };
        } catch (error) {
            throw new Error(`Request failed: ${error.message}`);
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
    
    /**
     * Load API discovery and OIDC configuration
     */
    async loadDiscovery() {
        const statusElement = document.getElementById('discoveryStatus');
        
        try {
            statusElement.textContent = '🔍 Loading OpenAPI specification...';
            await this.apiDiscovery.loadOpenAPISpec(this.config.serverUrl);
            
            statusElement.textContent = '🔍 Loading OIDC discovery document...';
            await this.apiDiscovery.loadDiscoveryDocument(this.config.serverUrl);
            
            // Generate dynamic test suites
            this.dynamicSuites = this.apiDiscovery.generateDynamicTestSuites();
            
            const endpointCount = Object.values(this.apiDiscovery.endpoints)
                .reduce((sum, arr) => sum + arr.length, 0);
            const capabilityCount = Object.keys(this.apiDiscovery.capabilities).length;
            
            statusElement.innerHTML = `✅ Discovered ${endpointCount} endpoints, ${capabilityCount} capabilities, ${this.dynamicSuites.length} dynamic test suites`;
            statusElement.className = 'discovery-success';
            
            // Initialize testers with discovery data
            this.adminTester = new AdminTester(this.config, this);
            this.performanceTester = new PerformanceTester(this.config, this);
            
        } catch (error) {
            statusElement.innerHTML = `❌ Discovery failed: ${error.message}`;
            statusElement.className = 'discovery-error';
            this.addLog(`API Discovery failed: ${error.message}`, 'error');
        }
    }
    
    /**
     * Run performance tests
     */
    async runPerformanceTests() {
        if (!this.performanceTester) {
            this.showNotification('Performance tester not initialized. Refresh discovery first.', 'error');
            return;
        }
        
        this.clearResults();
        this.updateExecutionStatus('running');
        this.addLog('Starting performance tests...', 'info');
        
        try {
            // Run comprehensive performance test suite
            const results = await this.performanceTester.runComprehensiveSuite();
            
            // Convert results to test format
            for (const [testType, endpoints] of Object.entries(results)) {
                for (const [endpoint, metrics] of Object.entries(endpoints)) {
                    const passed = metrics.metrics && 
                        metrics.metrics.successCount > metrics.metrics.errorCount;
                    
                    this.addTestResult({
                        suite: 'Performance Tests',
                        name: `${testType} - ${endpoint}`,
                        status: passed ? 'passed' : 'failed',
                        duration: metrics.metrics ? metrics.metrics.avgResponseTime : 0,
                        details: metrics,
                        error: !passed ? 'Performance below threshold' : null
                    });
                }
            }
            
            this.updateExecutionStatus('completed');
            this.updateResultsSummary();
            
        } catch (error) {
            this.updateExecutionStatus('error');
            this.addLog(`Performance tests failed: ${error.message}`, 'error');
        }
    }
    
    /**
     * Run admin API tests
     */
    async runAdminTests() {
        if (!this.adminTester) {
            this.showNotification('Admin tester not initialized. Refresh discovery first.', 'error');
            return;
        }
        
        this.clearResults();
        this.updateExecutionStatus('running');
        this.addLog('Starting admin API tests...', 'info');
        
        try {
            const results = await this.adminTester.runAllTests();
            
            // Convert results to test format
            for (const [category, tests] of Object.entries(results)) {
                if (typeof tests === 'object' && tests !== null) {
                    for (const [testName, result] of Object.entries(tests)) {
                        this.addTestResult({
                            suite: 'Admin API',
                            name: `${category} - ${testName}`,
                            status: result === true ? 'passed' : 'failed',
                            details: { result },
                            error: result !== true ? 'Operation failed' : null
                        });
                    }
                } else {
                    this.addTestResult({
                        suite: 'Admin API',
                        name: category,
                        status: tests === true ? 'passed' : 'failed',
                        details: { result: tests },
                        error: tests !== true ? 'Test failed' : null
                    });
                }
            }
            
            this.updateExecutionStatus('completed');
            this.updateResultsSummary();
            
        } catch (error) {
            this.updateExecutionStatus('error');
            this.addLog(`Admin tests failed: ${error.message}`, 'error');
        }
    }
    
    /**
     * Run dynamically discovered tests
     */
    async runDynamicTests() {
        if (this.dynamicSuites.length === 0) {
            this.showNotification('No dynamic tests available. Refresh discovery first.', 'error');
            return;
        }
        
        this.clearResults();
        this.updateExecutionStatus('running');
        this.addLog(`Running ${this.dynamicSuites.length} dynamic test suites...`, 'info');
        
        for (const suite of this.dynamicSuites) {
            await this.runTestSuite(suite.id, suite);
        }
        
        this.updateExecutionStatus('completed');
        this.updateResultsSummary();
    }
}

// Initialize the compliance tester when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.complianceTester = new ComplianceTester();
});