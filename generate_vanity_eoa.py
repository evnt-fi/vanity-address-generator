import multiprocessing as mp
import time
import math
import secrets
from eth_account import Account
from eth_utils import to_checksum_address
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from typing import List, Tuple
from collections import namedtuple

# TODO: Edit these values to match your desired pattern
prefix = "00000"  # The desired prefix for the vanity address
suffix = ""  # The desired suffix for the vanity address
match_case = True  # If True, checksum (case-sensitive) address matching is performed. Use True if only matching numbers to avoid cost of calling .lower() on address string.
max_derivations = 25  # Maximum number of derivations addresses to check for a given mnemonic
num_processes = max(1, mp.cpu_count() - 2)  # Use all available CPU cores except one (and save one for logging)

# Enable unaudited hdwallet features
# Account.enable_unaudited_hdwallet_features()

GeneratedAddresses = namedtuple("GeneratedAddresses", ["pk", "address", "index"])

def generate_eth_addresses_from_mnemonic(mnemonic, account=0, change=Bip44Changes.CHAIN_EXT, addresses_to_check=10) -> List[GeneratedAddresses]:
    # Generate seed from mnemonic
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

    # Generate the root key from the seed
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    
    # Derive the addresses from the seed
    addresses = []
    for address_index in range(addresses_to_check):
        bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(account).Change(change).AddressIndex(address_index)
        priv_key = bip44_acc_ctx.PrivateKey().Raw().ToHex()
        eth_account = Account.from_key(priv_key)
        addresses.append(GeneratedAddresses(priv_key, eth_account.address, address_index))
    return addresses

def check_vanity_pattern(address: str, prefix: str, suffix: str, match_case: bool = False):
    if not match_case:
        address = address.lower()
    return address.startswith(prefix) and address.endswith(suffix)

def worker(prefix, suffix, max_derivations, match_case, result_queue, stats_queue):
    local_guesses = 0
    while True:
        try:
            # Generate a random mnemonic
            mnemonic = Bip39MnemonicGenerator().FromEntropy(secrets.token_bytes(32)).ToStr()
                    
            # Derive max_derivations addresses for this mnemonic
            generated_addresses = generate_eth_addresses_from_mnemonic(mnemonic, addresses_to_check=max_derivations)
            for address in generated_addresses:
                local_guesses += 1
                if check_vanity_pattern(address.address[2:], prefix, suffix, match_case):
                    result_queue.put((address.index, address.address, mnemonic))
                    
            stats_queue.put(local_guesses)
            local_guesses = 0  # Reset local counter after reporting
        except Exception as e:
            print(f"Error in worker process: {e}")

def calculate_probability(prefix, suffix, match_case):
    if match_case:
        # For checksum addresses, we need to consider the case sensitivity
        lowercase_chars = sum(1 for c in prefix + suffix if c.islower())
        uppercase_chars = sum(1 for c in prefix + suffix if c.isupper())
        numeric_chars = sum(1 for c in prefix + suffix if c.isdigit())
        
        p_lower = 1 / 36  # Probability of a correct lowercase character
        p_upper = 1 / 36  # Probability of a correct uppercase character
        p_num = 1 / 16    # Probability of a correct numeric character
        
        prob = (p_lower ** lowercase_chars) * (p_upper ** uppercase_chars) * (p_num ** numeric_chars)
    else:
        # If not case-sensitive, each character has 1/16 probability
        total_chars = len(prefix) + len(suffix)
        prob = (1 / 16) ** total_chars
    
    return prob

def estimate_eta_50_percent(probability, guesses_per_second):
    # Number of guesses needed for 50% probability
    guesses_for_50_percent = math.log(0.5) / math.log(1 - probability)
    
    # Time to reach 50% probability
    eta_seconds = guesses_for_50_percent / guesses_per_second
    return eta_seconds

def format_time(seconds):
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    else:
        return f"{seconds/86400:.2f} days"

def log_progress(stats_queue, start_time, total_guesses, should_exit, prefix, suffix, match_case):
    last_log_time = time.time()
    probability = calculate_probability(prefix, suffix, match_case)
    while not should_exit.is_set():
        current_time = time.time()
        if current_time - last_log_time > 5:
            elapsed_time = current_time - start_time
            while not stats_queue.empty():
                total_guesses.value += stats_queue.get()
            guesses_per_second = total_guesses.value / elapsed_time
            eta_50_percent = estimate_eta_50_percent(probability, guesses_per_second)
                        
            print(f"\rElapsed Time: {format_time(elapsed_time)}, "
                  f"Total Guesses: {total_guesses.value:,}, "
                  f"Guesses/s: {guesses_per_second:,.2f}, "
                  f"Est. time to 50% probability: {format_time(eta_50_percent)}", end="", flush=True)
            
            last_log_time = current_time
        time.sleep(0.1)  # Sleep to reduce CPU usage of this process

def main(prefix: str, suffix: str, max_derivations: int = 5, match_case: bool = False, num_processes: int = None):
    if num_processes is None:
        num_processes = max(1, mp.cpu_count() - 1)  # Leave one CPU for logging
    
    start_time = time.time()
    result_queue = mp.Queue()
    stats_queue = mp.Queue()
    total_guesses = mp.Value('i', 0)
    should_exit = mp.Event()

    if not match_case:
        prefix = prefix.lower()
        suffix = suffix.lower()


    processes = []
    for _ in range(num_processes):
        p = mp.Process(target=worker, args=(prefix, suffix, max_derivations, match_case, result_queue, stats_queue))
        p.start()
        processes.append(p)

    # Start a process for logging progress
    log_process = mp.Process(target=log_progress, args=(stats_queue, start_time, total_guesses, should_exit, prefix, suffix, match_case))
    log_process.start()

    try:
        while True:
            result = result_queue.get()  # This will block until a result is available
            derivation_num, eoa_address, mnemonic_str = result
            elapsed_time = time.time() - start_time
            derivation_path = f"m/44'/60'/0'/0/{derivation_num}"

            print(f"\nMatch found after {total_guesses.value} guesses and {format_time(elapsed_time)}!")
            print(f"EOA Address: {eoa_address}")
            print(f"Derivation Path: {derivation_path}")
            print(f"Mnemonic:")
            mnemonic_words = mnemonic_str.split()
            for i in range(0, len(mnemonic_words), 3):
                print(" ".join(mnemonic_words[i:i+3]))
            
            print("---")

            start_time = time.time() # reset the start time for the next match
    except KeyboardInterrupt:
        print("\nProgram terminated by user")
    finally:
        # Signal all processes to exit
        should_exit.set()

        # Terminate all processes
        for p in processes:
            p.terminate()
        
        # Wait for log process to finish
        log_process.join()

        # Process remaining stats
        while not stats_queue.empty():
            total_guesses.value += stats_queue.get()

if __name__ == "__main__":
    print(f"Searching for EOA addresses matching: 0x{prefix}...{suffix}")
    print(f"Matching case: {match_case}")
    print(f"Checking up to {max_derivations} derivations")
    print(f"Using {num_processes} worker processes (+1 for logging).")
    print("Press Ctrl+C to stop the program")
    print("---")
    time.sleep(1)

    main(prefix, suffix, max_derivations, match_case, num_processes)
