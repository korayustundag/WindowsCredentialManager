package main

import (
	"fmt"
	"log"

	"your-module-path/credentialmanager"
)

func main()
{
	target := "MyApp"
	username := "user"
	password := "password"

	// Add credential
	if err := credentialmanager.AddCredential(target, username, password); err != nil {
		log.Fatalf("Failed to add credential: %v", err)
	}
	fmt.Println("Credential added successfully.")

	// Read credential
	cred, err := credentialmanager.ReadCredential(target)
	if err != nil {
		log.Fatalf("Failed to read credential: %v", err)
	}
	fmt.Printf("Read credential successfully.\nUsername: %s\nPassword: %s\n", cred.Username, cred.Password)

	// Validate credential
	valid, err := credentialmanager.ValidateCredential(target, username, password)
	if err != nil {
		log.Fatalf("Failed to validate credential: %v", err)
	}
	if valid {
		fmt.Println("Credential validation successful.")
	} else {
		fmt.Println("Credential validation failed.")
	}

	// Delete credential
	if err := credentialmanager.DeleteCredential(target); err != nil {
		log.Fatalf("Failed to delete credential: %v", err)
	}
	fmt.Println("Credential deleted successfully.")
}
