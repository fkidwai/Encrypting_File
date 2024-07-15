package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/akhilsharma90/file-encrypt/filecrypt"
	"golang.org/x/term"
)

func main() {
	// Check if at least one argument is provided
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	// Get the function name from the command-line arguments
	function := os.Args[1]

	// Switch to determine which function to call based on the argument
	switch function {
	case "help":
		// Print help message
		printHelp()
	case "encrypt":
		// Handle file encryption
		encryptHandle()
	case "decrypt":
		// Handle file decryption
		decrypthandle()
	default:
		// Print an error message if an unknown command is provided
		fmt.Println("Run encrypt to encrypt a file, and decrypt to decrypt a file.")
		os.Exit(1)
	}
}

// printHelp prints the usage information for the program
func printHelp() {
	fmt.Println("file encryption")
	fmt.Println("Simple file encrypter for your day-to-day needs.")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("")
	fmt.Println("\tgo run . encrypt /path/to/your/file")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("")
	fmt.Println("\t encrypt\tEncrypts a file given a password")
	fmt.Println("\t decrypt\tTries to decrypt a file using a password")
	fmt.Println("\t help\t\tDisplays help text")
	fmt.Println("")
}

// encryptHandle handles the file encryption process
func encryptHandle() {
	// Check if the file path is provided
	if len(os.Args) < 3 {
		fmt.Println("missing the path to the file. For more info, run go run . help")
		os.Exit(0)
	}

	// Get the file path from the command-line arguments
	file := os.Args[2]

	// Validate that the file exists
	if !validateFile(file) {
		panic("File not found")
	}

	// Get the encryption password from the user
	password := getPassword()
	fmt.Println("\nEncrypting...")

	// Call the Encrypt function from the filecrypt package
	filecrypt.Encrypt(file, password)
	fmt.Println("\nFile successfully protected.")
}

// decrypthandle handles the file decryption process
func decrypthandle() {
	// Check if the file path is provided
	if len(os.Args) < 3 {
		fmt.Println("missing the path to the file. For more info, run go run . help")
		os.Exit(0)
	}

	// Get the file path from the command-line arguments
	file := os.Args[2]

	// Validate that the file exists
	if !validateFile(file) {
		panic("File not found")
	}

	// Prompt the user to enter the password for decryption
	fmt.Print("Enter password:")
	password, _ := term.ReadPassword(0)
	fmt.Println("\nDecrypting...")

	// Call the Decrypt function from the filecrypt package
	filecrypt.Decrypt(file, password)
	fmt.Println("\nFile successfully decrypted.")
}

// getPassword prompts the user to enter and confirm a password
func getPassword() []byte {
	fmt.Print("Enter password:")
	password, _ := term.ReadPassword(0) // Read the password without echoing it

	fmt.Print("\nConfirm Password: ")
	password2, _ := term.ReadPassword(0) // Read the confirmation password

	// Validate that the passwords match
	if !validatePassword(password, password2) {
		fmt.Print("\nPasswords do not match. Please try again\n ")
		return getPassword() // Recursively prompt for the password again if they do not match
	}
	return password
}

// validatePassword checks if two byte slices (passwords) are equal
func validatePassword(password1 []byte, password2 []byte) bool {
	return bytes.Equal(password1, password2)
}

// validateFile checks if a file exists at the given path
func validateFile(file string) bool {
	_, err := os.Stat(file) // Get the file information
	return !os.IsNotExist(err) // Return true if the file exists, false otherwise
}
