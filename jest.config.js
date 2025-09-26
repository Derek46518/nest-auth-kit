module.exports = {
    rootDir: __dirname,
    testEnvironment: 'node',
    moduleFileExtensions: ['ts', 'js', 'json'],
    transform: {
        '^.+\\.(t|j)s$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.spec.json' }]
    },
    testMatch: ['<rootDir>/test/**/*.spec.ts', '<rootDir>/test/**/*.e2e-spec.ts'],
    moduleNameMapper: {
        '@/(.*)': '<rootDir>/src/$1',
        '^@derek/nest-auth-kit$': '<rootDir>/src',
        '^@derek/nest-auth-kit/(.*)$': '<rootDir>/src/$1'
    }
};
