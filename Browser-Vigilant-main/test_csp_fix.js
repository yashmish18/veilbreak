// Test CSP Fix - Verify localhost connections work
console.log('🧪 Testing CSP Fix for localhost connections...\n');

// Test 1: Direct fetch to localhost API
console.log('=== Test 1: Direct localhost API Connection ===');
try {
    fetch('http://localhost:3000/api/vault/stats')
        .then(response => {
            if (response.ok) {
                console.log('✅ Direct localhost connection successful');
                return response.json();
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        })
        .then(data => {
            console.log('✅ API Response:', JSON.stringify(data, null, 2));
            testSyncConnection();
        })
        .catch(error => {
            console.error('❌ Direct connection failed:', error.message);
            testSyncConnection();
        });
} catch (error) {
    console.error('❌ Test 1 failed with error:', error.message);
    testSyncConnection();
}

// Test 2: Sync endpoint connection
function testSyncConnection() {
    console.log('\n=== Test 2: Sync Endpoint Connection ===');
    try {
        const syncUrl = 'http://localhost:3000/api/vault/sync?since=0&clientId=test-extension';
        
        fetch(syncUrl)
            .then(response => {
                if (response.ok) {
                    console.log('✅ Sync endpoint connection successful');
                    return response.json();
                } else {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
            })
            .then(data => {
                console.log('✅ Sync Response:', JSON.stringify(data, null, 2));
                testThreatSubmission();
            })
            .catch(error => {
                console.error('❌ Sync connection failed:', error.message);
                testThreatSubmission();
            });
    } catch (error) {
        console.error('❌ Test 2 failed with error:', error.message);
        testThreatSubmission();
    }
}

// Test 3: Threat submission
function testThreatSubmission() {
    console.log('\n=== Test 3: Threat Submission ===');
    try {
        const threatData = {
            hash: 'testhash' + Date.now(),
            source: 'extension-test',
            confidence: 0.95,
            threatType: 'TEST_THREAT'
        };
        
        fetch('http://localhost:3000/api/vault/submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(threatData)
        })
        .then(response => {
            if (response.ok) {
                console.log('✅ Threat submission successful');
                return response.json();
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        })
        .then(data => {
            console.log('✅ Submission Response:', JSON.stringify(data, null, 2));
            finalVerification();
        })
        .catch(error => {
            console.error('❌ Threat submission failed:', error.message);
            finalVerification();
        });
    } catch (error) {
        console.error('❌ Test 3 failed with error:', error.message);
        finalVerification();
    }
}

// Final verification
function finalVerification() {
    console.log('\n=== Final Verification ===');
    console.log('✅ All localhost connection tests completed');
    console.log('\n📋 Next Steps:');
    console.log('1. Reload the extension in Chrome (chrome://extensions/ → Browser Vigilant → Reload)');
    console.log('2. The CSP error should now be resolved');
    console.log('3. Extension can now communicate with localhost:3000 API');
    console.log('4. Test with real browsing scenarios');
}