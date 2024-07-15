# File Encryption
This is a simple file encryption and decryption tool written in Go. It allows you to encrypt and decrypt files using a password.

## Installation

1. Make sure you have [Go](https://golang.org/dl/) installed on your machine.
2. Clone this repository:

    ```bash
    git clone https://github.com/fkidwai/Encrypting_File.git
    cd Encrypting_File
    ```

3. Install the required Go modules:

    ```bash
    go mod tidy
    ```

### Encryption

```bash
# Encrypts a file
$ go run . encrypt image.jpeg
```

### Decryption

```bash
# Decrypts a file
$ go run . decrypt image.jpeg
```