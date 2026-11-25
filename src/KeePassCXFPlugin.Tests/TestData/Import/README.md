# Import test data

Put CXF `.json` files here or in any subfolder. The `ImportTestData` test recursively loads every JSON file in this directory into a fresh KeePass database and passes as long as loading completes without an error; it does not require the file to contain a supported passkey. Keep test credentials synthetic; do not put real passkeys or private keys in this folder.
