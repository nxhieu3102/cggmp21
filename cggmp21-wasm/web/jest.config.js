module.exports = {
  // Set test environment to jsdom for browser simulation
  testEnvironment: 'jsdom',
  
  // Transform files with Babel for ES6+ support
  transform: {},
  
  // Setup files to run before tests
  setupFiles: [],
  
  // Ignore paths for transforming
  transformIgnorePatterns: [
    '/node_modules/',
    '\\.pnp\\.[^\\/]+$'
  ],
  
  // Modules to mock
  moduleNameMapper: {
    // Map WebAssembly modules to mock implementations for testing
    '\\.wasm$': '<rootDir>/__mocks__/wasm-mock.js'
  },
  
  // Files to run after the test framework is set up
  setupFilesAfterEnv: [],
  
  // Test match patterns
  testMatch: [
    '<rootDir>/test.js',
    '<rootDir>/__tests__/**/*.js'
  ],
  
  // Test coverage configuration
  collectCoverage: false,
  
  // Files to skip in coverage calculation
  coveragePathIgnorePatterns: [
    '/node_modules/',
    '/test/',
    '__mocks__'
  ],
  
  // Verbosity of test output
  verbose: true
}; 
