module.exports = {
  clearMocks: true,
  modulePathIgnorePatterns: ['<rootDir>/dist/'],
  preset: 'ts-jest',
  moduleNameMapper: {
    "^web-worker:.*$": '<rootDir>/src/test/worker.ts'
  },
  testEnvironment: 'node',
};
