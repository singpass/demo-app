// IMPORTANT NOTE:
//
// Please DO NOT hardcode private keys in your code.
// Private keys are secrets. Store private keys in a safe place (e.g. SecretsManager, Vault, ...).
// The below private keys are hardcoded here for the convenience of the demo.
// Please DO NOT hardcode private keys in your code.

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
let config;

try {
  config = JSON.parse(fs.readFileSync(path.join(__filename, '../../../config.json')));
  console.info('[INFO]: config is imported.');
} catch (e) {
  config = {};
  console.error('[ERROR]: facing error when parsing config.', e);
}

export default config;
