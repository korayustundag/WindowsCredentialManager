const ffi = require('ffi-napi');
const ref = require('ref-napi');
const StructType = require('ref-struct-di')(ref);

// Constants
const CRED_TYPE_GENERIC = 1;
const CRED_PERSIST_LOCAL_MACHINE = 2;

// CREDENTIAL structure
const CREDENTIAL = StructType({
  Flags: 'uint32',
  Type: 'uint32',
  TargetName: 'pointer',
  Comment: 'pointer',
  LastWritten: 'uint64',
  CredentialBlobSize: 'uint32',
  CredentialBlob: 'pointer',
  Persist: 'uint32',
  AttributeCount: 'uint32',
  Attributes: 'pointer',
  TargetAlias: 'pointer',
  UserName: 'pointer'
});

// Load Advapi32.dll
const advapi32 = ffi.Library('Advapi32.dll', {
  'CredWriteW': ['bool', ['pointer', 'uint32']],
  'CredReadW': ['bool', ['string', 'uint32', 'uint32', 'pointer']],
  'CredFree': ['void', ['pointer']],
  'CredDeleteW': ['bool', ['string', 'uint32', 'uint32']]
});

function stringToWideChar(str) {
  return Buffer.from(str + '\u0000', 'ucs2');
}

function addCredential(target, username, password) {
  const targetBuf = stringToWideChar(target);
  const usernameBuf = stringToWideChar(username);
  const passwordBuf = stringToWideChar(password);

  const credential = new CREDENTIAL({
    Flags: 0,
    Type: CRED_TYPE_GENERIC,
    TargetName: targetBuf,
    UserName: usernameBuf,
    CredentialBlobSize: passwordBuf.length,
    CredentialBlob: passwordBuf,
    Persist: CRED_PERSIST_LOCAL_MACHINE,
    AttributeCount: 0,
    Attributes: null,
    Comment: null,
    LastWritten: 0,
    TargetAlias: null
  });

  const result = advapi32.CredWriteW(credential.ref(), 0);
  if (!result) {
    throw new Error('Failed to write credential');
  }
}

function readCredential(target) {
  const credPtr = ref.alloc('pointer');
  const result = advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, credPtr);
  if (!result) {
    throw new Error('Failed to read credential');
  }

  const cred = credPtr.deref().deref();
  const username = cred.UserName.readCString(0);
  const password = cred.CredentialBlob.readCString(0, cred.CredentialBlobSize);
  advapi32.CredFree(credPtr.deref());

  return { username, password };
}

function deleteCredential(target) {
  const result = advapi32.CredDeleteW(target, CRED_TYPE_GENERIC, 0);
  if (!result) {
    throw new Error('Failed to delete credential');
  }
}

function validateCredential(target, username, password) {
  try {
    const cred = readCredential(target);
    return cred.username === username && cred.password === password;
  } catch (err) {
    return false;
  }
}

// Exports
module.exports = {
  addCredential,
  readCredential,
  deleteCredential,
  validateCredential
};
