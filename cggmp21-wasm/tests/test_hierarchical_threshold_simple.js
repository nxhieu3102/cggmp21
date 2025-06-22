#!/usr/bin/env node

// Simple Node.js test script for hierarchical threshold key generation
// Run with: node test_hierarchical_threshold_simple.js

const { runTest, testConfigurations, validateConfiguration } = require('./test_stateful_hierarchical_threshold_keygen.js');

async function runSimpleTest() {
    console.log('🏛️ CGGMP21 Hierarchical Threshold Key Generation - Simple Test');
    console.log('==============================================================\n');
    
    try {
        // Test configuration validation first
        console.log('📋 Testing configuration validation...');
        const smallConfig = testConfigurations.small.parties;
        const validationResult = validateConfiguration(smallConfig);
        console.log(`✅ Configuration validation passed: ${validationResult.t}-of-${validationResult.n} with ${validationResult.validSets} valid authorized sets\n`);
        
        // Run the small test (fastest)
        console.log('🧪 Running small configuration test (2-of-3 hierarchical threshold)...');
        const startTime = Date.now();
        const result = await runTest('small');
        const endTime = Date.now();
        const duration = endTime - startTime;
        
        console.log('\n🎉 Test Results:');
        console.log(`⏱️  Duration: ${duration}ms`);
        console.log(`🏛️  Configuration: ${result.config.t}-of-${result.config.n} hierarchical threshold`);
        console.log(`📊 Valid authorized sets: ${result.config.validSets}`);
        console.log(`🔑 Generated key shares: ${result.keyShares.length}`);
        console.log(`🔐 Commitments: ${result.commitments.length}`);
        console.log(`📝 Decommitments: ${result.decommitments.length}`);
        console.log(`🔒 Schnorr proofs: ${result.schnorrProofs.length}`);
        
        // Validate that all key shares were generated
        result.keyShares.forEach((keyShare, idx) => {
            if (keyShare && typeof keyShare === 'object') {
                console.log(`✅ Party ${idx}: Key share generated successfully`);
            } else {
                throw new Error(`❌ Invalid key share for party ${idx}`);
            }
        });
        
        console.log('\n🎊 Simple test completed successfully!');
        console.log('✅ Hierarchical threshold key generation is working correctly');
        
    } catch (error) {
        console.error('\n💥 Test failed:', error.message);
        if (error.stack) {
            console.error('📋 Stack trace:', error.stack);
        }
        process.exit(1);
    }
}

// Run the test if this script is executed directly
if (require.main === module) {
    runSimpleTest().catch(error => {
        console.error('Fatal error:', error);
        process.exit(1);
    });
}

module.exports = { runSimpleTest }; 
