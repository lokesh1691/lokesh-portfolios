/**
 * Usage: npm run hash-password -- "your-real-password"
 * Copy the output into ADMIN_PASSWORD_HASH in your .env file.
 * Never put the plaintext password in any file that gets committed.
 */
const bcrypt = require('bcryptjs');

const password = process.argv[2];
if (!password) {
  console.error('Usage: npm run hash-password -- "your-password"');
  process.exit(1);
}

bcrypt.hash(password, 12).then((hash) => {
  console.log('\nAdd this to your .env file:\n');
  console.log(`ADMIN_PASSWORD_HASH=${hash}\n`);
});
