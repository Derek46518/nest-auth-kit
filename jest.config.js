module.exports = {
    rootDir: '../..',
    testEnvironment: 'node',
    moduleFileExtensions: ['js', 'json', 'ts'],
    transform: {
        '^.+\\.(t|j)s$': 'ts-jest'
    },
    testRegex: 'packages/nest-auth-kit/test/.*\\.e2e-spec\\.ts$',
    moduleNameMapper: {
        '@/(.*)': '<rootDir>/src/$1',
        '^nest-auth-kit(.*)$': '<rootDir>/packages/nest-auth-kit/src$1'
    }
};
