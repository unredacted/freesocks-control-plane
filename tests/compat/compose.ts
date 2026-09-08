/** The disposable compat stack: the Remnawave test panel plus the compat overlay. */
export const compose = [
  'compose',
  '-p',
  'fcp-compat',
  '-f',
  'docker-compose.remnawave-test.yml',
  '-f',
  'docker-compose.compat.yml',
];
