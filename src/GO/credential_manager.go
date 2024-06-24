package credentialmanager

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Credential structure
type Credential struct {
	Target   string
	Username string
	Password string
}

var (
	credui = syscall.NewLazyDLL("credui.dll")
	creduiCredWriteW = credui.NewProc("CredWriteW")
	creduiCredReadW  = credui.NewProc("CredReadW")
	creduiCredDeleteW = credui.NewProc("CredDeleteW")
)

// AddCredential adds a new credential
func AddCredential(target, username, password string) error {
	targetPtr, _ := syscall.UTF16PtrFromString(target)
	usernamePtr, _ := syscall.UTF16PtrFromString(username)
	passwordPtr, _ := syscall.UTF16PtrFromString(password)

	credential := &syscall.Credential{
		TargetName:      targetPtr,
		UserName:        usernamePtr,
		CredentialBlob:  (*byte)(unsafe.Pointer(passwordPtr)),
		CredentialBlobSize: uint32(len(password) * 2),
		Persist:         syscall.CRED_PERSIST_LOCAL_MACHINE,
		Type:            syscall.CRED_TYPE_GENERIC,
	}

	r1, _, err := creduiCredWriteW.Call(uintptr(unsafe.Pointer(credential)), 0)
	if r1 == 0 {
		return fmt.Errorf("failed to write credential: %v", err)
	}
	return nil
}

// ReadCredential reads a credential
func ReadCredential(target string) (*Credential, error) {
	targetPtr, _ := syscall.UTF16PtrFromString(target)
	var pcred *syscall.Credential

	r1, _, err := creduiCredReadW.Call(uintptr(unsafe.Pointer(targetPtr)), uintptr(syscall.CRED_TYPE_GENERIC), 0, uintptr(unsafe.Pointer(&pcred)))
	if r1 == 0 {
		return nil, fmt.Errorf("failed to read credential: %v", err)
	}
	defer syscall.CredFree(pcred)

	username := syscall.UTF16ToString((*[1024]uint16)(unsafe.Pointer(pcred.UserName))[:])
	password := syscall.UTF16ToString((*[1024]uint16)(unsafe.Pointer(pcred.CredentialBlob))[:pcred.CredentialBlobSize/2])

	return &Credential{
		Target:   target,
		Username: username,
		Password: password,
	}, nil
}

// DeleteCredential deletes a credential
func DeleteCredential(target string) error {
	targetPtr, _ := syscall.UTF16PtrFromString(target)
	r1, _, err := creduiCredDeleteW.Call(uintptr(unsafe.Pointer(targetPtr)), uintptr(syscall.CRED_TYPE_GENERIC), 0)
	if r1 == 0 {
		return fmt.Errorf("failed to delete credential: %v", err)
	}
	return nil
}

// ValidateCredential validates a credential
func ValidateCredential(target, username, password string) (bool, error) {
	cred, err := ReadCredential(target)
	if err != nil {
		return false, err
	}
	return cred.Username == username && cred.Password == password, nil
}
