# Authly Compliance Tester - Manual Testing Guide

## Quick Start

### 1. Access the Application
Open your browser and navigate to: **http://localhost:8080**

You should see a professional dashboard with:
- Left sidebar with navigation menu
- Main dashboard with stats cards
- Quick action buttons
- Test results section

## Step-by-Step Testing Guide

### Test 1: Run All Compliance Tests
**Purpose**: Verify all test suites execute without duplicates

1. **Click** the "🚀 Run All Tests" button in Quick Actions
2. **Watch** the execution panel slide up from bottom
3. **Observe**:
   - Progress bar filling up
   - Live logs appearing
   - Test count should show "22 / 22 tests" (not duplicated)
4. **Expected Results**:
   - 6 tests PASS ✅
   - 8 tests FAIL ❌ (these are real Authly issues)
   - 0 skipped
   - Total: 14 tests (OAuth 2.1 suite only shows once)

### Test 2: Individual Suite Testing
**Purpose**: Test single suite execution

1. **Navigate** to "Compliance Tests" in sidebar
2. **Find** "OAuth 2.1 + PKCE" card
3. **Click** "Run Tests" button
4. **Verify**:
   - Only 7 tests run (not 14)
   - Execution panel shows progress
   - Results appear in real-time

### Test 3: Copy Results to Clipboard
**Purpose**: Verify clipboard functionality

1. **Run** any test suite first
2. **Wait** for completion
3. **Click** "Clear" button next to "Recent Test Results"
4. **Run** tests again
5. **Click** on any result item
6. **Press** Ctrl+C (or Cmd+C on Mac)
7. **Open** a text editor
8. **Paste** - you should see formatted test results

### Test 4: Navigation Testing
**Purpose**: Verify UI navigation works

1. **Click** each sidebar item:
   - 📊 Dashboard
   - ✅ Compliance Tests
   - ⚡ Performance
   - 👤 Admin APIs
   - 🔍 API Discovery
   - ⚙️ Configuration

2. **Verify** for each:
   - Page title updates in top bar
   - Content area changes
   - Navigation item highlights

### Test 5: Configuration Modal
**Purpose**: Test settings management

1. **Click** "⚙️ Configuration" in sidebar
2. **Verify** modal appears with fields:
   - Server URL
   - Client ID
   - Client Secret
   - Redirect URI
   - Scopes
   - Test Username
   - Test Password
3. **Change** Server URL to "http://localhost:9999"
4. **Click** "Save Configuration"
5. **Refresh** the page
6. **Click** Configuration again
7. **Verify** your changes persisted

### Test 6: Execution Controls
**Purpose**: Test pause/stop functionality

1. **Start** "Run All Tests"
2. **Quickly click** "Pause" button in execution panel
3. **Verify** execution pauses
4. **Click** "Resume" (same button)
5. **Verify** execution continues
6. **Start** new test
7. **Click** "Stop" button
8. **Verify** execution stops immediately

### Test 7: Export Report
**Purpose**: Test JSON export

1. **Run** any test suite
2. **Click** "Export" button in top bar
3. **Verify** JSON file downloads
4. **Open** the file
5. **Check** it contains:
   - Timestamp
   - Configuration
   - Test results
   - Summary statistics

### Test 8: API Discovery Verification
**Purpose**: Confirm dynamic discovery works

1. **Look** at top bar for discovery badge
2. **Should show**: "42 endpoints discovered"
3. **Check** execution logs for discovery messages
4. **Verify** no discovery errors in console

### Test 9: Responsive Design
**Purpose**: Test mobile responsiveness

1. **Open** browser developer tools (F12)
2. **Toggle** device toolbar (Ctrl+Shift+M)
3. **Select** "iPhone 12 Pro"
4. **Verify**:
   - Sidebar collapses
   - Cards stack vertically
   - All buttons remain clickable
   - Text remains readable

### Test 10: Error Scenarios
**Purpose**: Test error handling

1. **Stop** Authly container:
   ```bash
   docker stop authly-standalone
   ```
2. **Run** tests in the UI
3. **Verify**:
   - Network errors are caught
   - Clear error messages appear
   - UI doesn't crash
4. **Restart** Authly:
   ```bash
   docker start authly-standalone
   ```

## Expected Test Results Explained

### Tests That Should PASS ✅
1. **PKCE is Mandatory** - Authly correctly requires PKCE
2. **State Parameter Preserved** - State is maintained through flow
3. **Only Authorization Code Flow** - Implicit/hybrid blocked

### Tests That Should FAIL ❌ (Authly bugs)
1. **Only S256 Method Allowed** - Authly accepts insecure `plain` method
2. **S256 Method Works** - May show network error if CORS issue
3. **Redirect URI Exact Match** - Authly uses loose matching
4. **State Parameter Required** - Authly doesn't enforce state

## Console Commands for Debugging

Open browser console (F12) and run:

```javascript
// Check current test results
console.log(complianceTester.testResults);

// View configuration
console.log(complianceTester.config);

// Manually trigger discovery
await complianceTester.loadDiscovery();

// Get test suite details
console.log(TestSuites.getAllSuites());

// Check API discovery results
console.log(complianceTester.apiDiscovery.endpoints);
```

## Docker Commands for Testing

```bash
# View logs
docker logs authly-compliance-tester

# Check network connectivity
docker network inspect authly-network

# Restart tester
docker restart authly-compliance-tester

# Check container status
docker ps | grep authly

# Access container shell
docker exec -it authly-compliance-tester sh
```

## Visual Indicators to Verify

### ✅ Working Correctly
- Green "Connected to Authly" in sidebar
- "42 endpoints discovered" badge
- Execution panel slides up smoothly
- Progress bar animates during tests
- Results show immediately after each test

### ❌ Issues to Watch For
- Red connection status
- "Discovery failed" message
- Execution panel stuck open
- Progress bar not moving
- Duplicate test results (bug is fixed, shouldn't happen)

## Performance Benchmarks

During testing, you should observe:
- Page load: < 1 second
- Test execution: 2-3 seconds for all suites
- UI interactions: Instant response
- API discovery: < 2 seconds

## Troubleshooting

### If tests won't run:
1. Check Authly is running: `docker ps`
2. Verify network: `docker network ls`
3. Check browser console for errors
4. Try refreshing the page
5. Clear browser cache

### If UI looks broken:
1. Hard refresh: Ctrl+Shift+R
2. Check CSS loaded: View page source
3. Verify no JavaScript errors in console
4. Try different browser

### If results are wrong:
1. Clear results and re-run
2. Check individual suite vs all suites
3. Verify no duplicate execution
4. Check network tab for API calls

## Success Criteria

Your manual testing is successful if:
- ✅ All navigation works smoothly
- ✅ Tests run without duplicates
- ✅ Results show 42.9% pass rate (6/14 passed)
- ✅ Execution panel animates properly
- ✅ Export and clipboard features work
- ✅ Configuration persists after refresh
- ✅ No console errors during normal operation
- ✅ UI remains responsive during test execution

---
*Testing Time: ~10-15 minutes*
*Required: Browser + Docker*
*Containers: authly-standalone, authly-compliance-tester*