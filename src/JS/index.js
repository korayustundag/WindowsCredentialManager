const cm = require('./credential_manager');

const target = 'MyApp';
const username = 'user';
const password = 'password';

// Add credential
try {
  cm.addCredential(target, username, password);
  console.log('Credential added successfully.');
} catch (err) {
  console.error(`Failed to add credential: ${err.message}`);
}

// Read credential
try {
  const cred = cm.readCredential(target);
  console.log('Read credential successfully.');
  console.log(`Username: ${cred.username}`);
  console.log(`Password: ${cred.password}`);
} catch (err) {
  console.error(`Failed to read credential: ${err.message}`);
}

// Validate credential
try {
  const valid = cm.validateCredential(target, username, password);
  console.log(valid ? 'Credential validation successful.' : 'Credential validation failed.');
} catch (err) {
  console.error(`Failed to validate credential: ${err.message}`);
}

// Delete credential
try {
  cm.deleteCredential(target);
  console.log('Credential deleted successfully.');
} catch (err) {
  console.error(`Failed to delete credential: ${err.message}`);
}
