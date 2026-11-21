# Syntecxhub Password Manager

A local command-line password manager built in Python as part of the Syntecxhub Cyber Security Internship (Week 1, Project 2).

## Features
- Master password protected vault
- AES-256-GCM encryption
- Key derived from the master password using Scrypt (random salt)
- Encrypted JSON storage on disk (vault.enc)
- Add, get, search, list and delete entries
- Secure random password generator

## Setup
pip install -r requirements.txt

## Usage
python password_manager.py init
python password_manager.py add Gmail user@example.com --generate
python password_manager.py add Facebook myusername
python password_manager.py list
python password_manager.py search gm
python password_manager.py get Gmail
python password_manager.py delete Facebook

## How it works
1. The master password and a random salt are passed through Scrypt to create a 256-bit key.
2. Entries are converted to JSON and encrypted with AES-GCM using a random nonce.
3. Only the salt, nonce and ciphertext are saved in vault.enc. The master password and key are never stored.
4. A wrong password or a modified file fails authentication and access is denied.

## Security notes
- If the master password is forgotten, the data cannot be recovered.
- vault.enc is excluded from the repository via .gitignore.
- This is an educational project.