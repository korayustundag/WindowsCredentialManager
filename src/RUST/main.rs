mod credential_manager;
use credential_manager::CredentialManager;

fn main()
  {
    let target = "MyApp";
    let username = "user";
    let password = "password";

    // Kimlik bilgisi ekleme
    match CredentialManager::add_credential(target, username, password){
        Ok(_) => println!("Credential added successfully."),
        Err(e) => eprintln!("Failed to add credential: {}", e),
    }

    match CredentialManager::read_credential(target) {
        Ok((read_username, read_password)) => {
            println!("Read credential successfully.");
            println!("Username: {}", read_username);
            println!("Password: {}", read_password);
        }
        Err(e) => eprintln!("Failed to read credential: {}", e),
    }

    match CredentialManager::validate_credential(target, username, password) {
        Ok(true) => println!("Credential validation successful."),
        Ok(false) => println!("Credential validation failed."),
        Err(e) => eprintln!("Failed to validate credential: {}", e),
    }

    match CredentialManager::delete_credential(target) {
        Ok(_) => println!("Credential deleted successfully."),
        Err(e) => eprintln!("Failed to delete credential: {}", e),
    }
}
