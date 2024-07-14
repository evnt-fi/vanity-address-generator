# vanity-address-generator
Generate private keys for Ethereum EOA's that will be able to deploy vanity contract addresses, or generate mnemonic seeds that will create vanity EOAs.


(Optional) Setup virtual environment and install dependencies
```sh
python3 -m venv venv --prompt vanity-addr-gen
source venv/bin/activate
pip install -r requirements.txt
```

---

# Generate vanity contract 

This will find a private key and nonce for an EOA that will be able to deploy a contract with a given prefix and suffix.

Edit `generate_vanity_contract_deployer.py` to set the desired prefix, suffix, and max nonce. 

Then run the script:
```sh
python generate_vanity_contract_deployer.py
```

---

# Generate vanity EOAs

This will find a 12-word mnemonic seed that will generate an EOA with a public key that matches the given prefix and suffix.

Edit `generate_vanity_eoa.py` to set the desired prefix, suffix, and number of derivation addresses to check.

Then run the script:
```sh
python generate_vanity_eoa.py
```

---

## Contract Address Checker

This script takes an EOA address + nonce pair gives the contract address that would be deployed.

```sh
python calculate_contract_address.py
```