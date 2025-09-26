module.exports = {
    rootDir: __dirname,
    preset: 'ts-jest',
    testEnvironment: 'node',
    moduleFileExtensions: ['ts', 'js', 'json'],
    testMatch: ['<rootDir>/test/**/*.spec.ts', '<rootDir>/test/**/*.e2e-spec.ts'],
    moduleNameMapper: {
        '@/(.*)': '<rootDir>/src/$1'
    }
};
