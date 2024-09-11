module.exports = {
  root: true,
  env: { browser: true, node: true, es6: true },
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  extends: ['eslint:recommended', 'prettier'],
  plugins: ['prettier'],
  rules: {
    'prefer-const': 'error',
    'prefer-template': 'error',
    eqeqeq: 'error',
  },
};
