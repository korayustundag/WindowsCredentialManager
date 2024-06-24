import ffi from 'ffi-napi';
import ref from 'ref-napi';
import StructType from 'ref-struct-di';

const Struct = StructType(ref);

// Constants
const CRED_TYPE_GENERIC = 1;
const CRED_PERSIST_LOCAL_MACHINE = 2;

// CREDENTIAL structure
const CREDENTIAL = Struct({
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

function stringToWideChar(str: string): Buffer {
  return Buffer.from(str + '\u0000', 'ucs2');
}

export function addCredential(target: string, username: string, password: string): void {
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

export function readCredential(target: string): { username: string; password: string } | null {
  const credPtr = ref.alloc('pointer');
  const result = advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, credPtr);
  if (!result) {
    return null;
  }

  const cred = credPtr.deref() as any;
  const credential = new CREDENTIAL(cred);
  const username = credential.UserName.readCString(0);
  const password = credential.CredentialBlob.readCString(0, credential.CredentialBlobSize);

  advapi32.CredFree(credPtr.deref());

  return { username, password };
}

export function deleteCredential(target: string): void {
  const result = advapi32.CredDeleteW(target, CRED_TYPE_GENERIC, 0);
  if (!result) {
    throw new Error('Failed to delete credential');
  }
}

export function validateCredential(target: string, username: string, password: string): boolean {
  const credential = readCredential(target);
  if (!credential) {
    return false;
  }
  return credential.username === username && credential.password === password;
}
