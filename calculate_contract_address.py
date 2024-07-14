import sys
from eth_utils import keccak, to_checksum_address, to_bytes
import rlp

def calculate_contract_address(eoa_address, nonce):
    """
    Calculate the contract address that would be created by the given EOA address and nonce.
    
    :param eoa_address: The address of the EOA deploying the contract
    :param nonce: The nonce of the EOA for this deployment
    :return: The calculated contract address
    """
    # Ensure the EOA address is in the correct format
    eoa_address = to_checksum_address(eoa_address)
    
    # RLP encode the address and nonce
    rlp_encoded = rlp.encode([to_bytes(hexstr=eoa_address), nonce])
    
    # Keccak-256 hash the RLP encoded data
    hash_result = keccak(rlp_encoded)
    
    # Take the last 20 bytes (40 hex characters) of the hash result
    contract_address = '0x' + hash_result[-20:].hex()
    
    # Return the contract address in checksum format
    return to_checksum_address(contract_address)

def print_result(eoa_address, nonce, contract_address):
    print(f"\nEOA Address: {eoa_address}")
    print(f"Nonce: {nonce}")
    print(f"Contract Address: {contract_address}\n")

def interactive_mode():
    print("Ethereum Contract Address Checker")
    print("=================================")
    
    while True:
        eoa_address = input("Enter the EOA address (or 'q' to quit): ")
        if eoa_address.lower() == 'q':
            break
        
        try:
            nonce = int(input("Enter the nonce: "))
            
            contract_address = calculate_contract_address(eoa_address, nonce)
            print_result(eoa_address, nonce, contract_address)
        except ValueError:
            print("Invalid input. Please enter a valid address and nonce.")
        except Exception as e:
            print(f"An error occurred: {e}")
        
        print("---------------------------------")

def main():
    if len(sys.argv) == 3:
        # Command-line mode
        eoa_address = sys.argv[1]
        try:
            nonce = int(sys.argv[2])
            contract_address = calculate_contract_address(eoa_address, nonce)
            print_result(eoa_address, nonce, contract_address)
        except ValueError:
            print("Invalid nonce. Please provide a valid integer.")
        except Exception as e:
            print(f"An error occurred: {e}")
    elif len(sys.argv) == 1:
        # Interactive mode
        interactive_mode()
    else:
        print("Usage: python script.py [EOA_ADDRESS NONCE]")
        print("If no arguments are provided, the script will run in interactive mode.")

if __name__ == "__main__":
    main()