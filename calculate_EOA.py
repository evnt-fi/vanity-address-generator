import sys
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from eth_account import Account

def generate_eoa_address(mnemonic, derivation_number):
    """
    Generate an EOA address from the given mnemonic and derivation number.
    
    :param mnemonic: The mnemonic phrase
    :param derivation_number: The derivation number (address index)
    :return: The generated EOA address
    """
    # Generate seed from mnemonic
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

    # Generate the root key from the seed
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    
    # Derive the address
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(derivation_number)
    private_key = bip44_acc_ctx.PrivateKey().Raw().ToHex()
    
    # Generate Ethereum address
    account = Account.from_key(private_key)
    return account.address

def print_result(mnemonic, derivation_number, eoa_address):
    print(f"\nMnemonic: {mnemonic}")
    print(f"Derivation Path: m/44'/60'/0'/0/{derivation_number}")
    print(f"EOA Address: {eoa_address}\n")

def get_multiline_input(prompt):
    print(prompt)
    print("(Press Enter twice to finish input)")
    lines = []
    while True:
        line = input()
        if line:
            lines.append(line)
        else:
            break
    return ' '.join(lines)

def interactive_mode():
    print("Ethereum Vanity EOA Checker")
    print("===========================")
    
    while True:
        mnemonic = get_multiline_input("Enter the mnemonic phrase (or 'q' to quit):")
        if mnemonic.lower() == 'q':
            break
        
        try:
            derivation_number = int(input("Enter the derivation number: "))
            
            eoa_address = generate_eoa_address(mnemonic, derivation_number)
            print_result(mnemonic, derivation_number, eoa_address)
        except ValueError:
            print("Invalid input. Please enter a valid mnemonic and derivation number.")
        except Exception as e:
            print(f"An error occurred: {e}")
        
        print("---------------------------------")

def main():
    if len(sys.argv) == 3:
        # Command-line mode
        mnemonic = sys.argv[1]
        try:
            derivation_number = int(sys.argv[2])
            eoa_address = generate_eoa_address(mnemonic, derivation_number)
            print_result(mnemonic, derivation_number, eoa_address)
        except ValueError:
            print("Invalid derivation number. Please provide a valid integer.")
        except Exception as e:
            print(f"An error occurred: {e}")
    elif len(sys.argv) == 1:
        # Interactive mode
        interactive_mode()
    else:
        print("Usage: python script.py [MNEMONIC DERIVATION_NUMBER]")
        print("If no arguments are provided, the script will run in interactive mode.")

if __name__ == "__main__":
    main()