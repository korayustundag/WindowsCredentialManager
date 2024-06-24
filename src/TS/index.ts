import * as cm from './credential_manager';

const target = 'MyApp';
const username = 'user';
const password = 'password';

// Add credential
try {
  cm.addCredential(target, username, password);
  console.log('Credential added successfully.');
} catch (err) {
  console.error(`Failed to add credential: ${(err as Error).message}`);
}

// Read credential
try {
  const cred = cm.readCredential(target);
  if (cred) {
    console.log('Read credential successfully.');
    console.log(`Username: ${cred.username}`);
    console.log(`Password: ${cred.password}`);
  } else {
    console.log('Failed to read credential.');
  }
} catch (err) {
  console.error(`Failed to read credential: ${(err as Error).message}`);
}

// Validate credential
try {
  const valid = cm.validateCredential(target, username, password);
  console.log(valid ? 'Credential validation successful.' : 'Credential validation failed.');
} catch (err) {
  console.error(`Failed to validate credential: ${(err as Error).message}`);
}

// Delete credential
try {
  cm.deleteCredential(target);
  console.log('Credential deleted successfully.');
} catch (err) {
  console.error(`Failed to delete credential: ${(err as Error).message}`);
}
