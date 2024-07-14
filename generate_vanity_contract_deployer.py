import secrets
from eth_account import Account
from eth_utils import keccak, to_checksum_address, to_bytes
import rlp
import time
import multiprocessing as mp
import math

# TODO: Edit these values to match your desired pattern
prefix = "B00B5"  # The desired prefix for the vanity address
suffix = ""  # The desired suffix for the vanity address
match_case = True # if True, checksum (case-sensitive) address matching is performed
max_nonce = 5
num_processes = max(1, mp.cpu_count() - 2)  # Use all available CPU cores except one (and save one for logging)

def generate_random_private_key():
    return secrets.token_bytes(32)

def get_eoa_address(private_key):
    return Account.from_key(private_key).address

def calculate_contract_address(eoa_address, nonce):
    return keccak(rlp.encode([to_bytes(hexstr=eoa_address), int(nonce)]))[-20:].hex()

def check_vanity_pattern(address: str, prefix: str, suffix: str, match_case: bool = False):
    if match_case:
        address = to_checksum_address(address)
    else:
        address = address.lower()
        prefix = prefix.lower()
        suffix = suffix.lower()
    return address.startswith(prefix) and address.endswith(suffix)

    
def worker(prefix, suffix, max_nonce, match_case, result_queue, stats_queue):
    local_guesses = 0
    while True:
        private_key = generate_random_private_key()
        eoa_address = get_eoa_address(private_key)
        
        for nonce in range(max_nonce):
            local_guesses += 1
            contract_address = calculate_contract_address(eoa_address, nonce) # does not start with 0x
            if check_vanity_pattern(contract_address, prefix, suffix, match_case):
                result_queue.put((private_key, eoa_address, nonce, contract_address))
        
        stats_queue.put(local_guesses)
        local_guesses = 0  # Reset local counter after reporting

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

def main(prefix, suffix, max_nonce=50, match_case=False, num_processes=None):
    if num_processes is None:
        num_processes = max(1, mp.cpu_count() - 1)  # Leave one CPU for logging
    
    start_time = time.time()
    result_queue = mp.Queue()
    stats_queue = mp.Queue()
    total_guesses = mp.Value('i', 0)
    should_exit = mp.Event()

    processes = []
    for _ in range(num_processes):
        p = mp.Process(target=worker, args=(prefix, suffix, max_nonce, match_case, result_queue, stats_queue))
        p.start()
        processes.append(p)

    # Start a process for logging progress
    log_process = mp.Process(target=log_progress, args=(stats_queue, start_time, total_guesses, should_exit, prefix, suffix, match_case))
    log_process.start()

    try:
        while True:
            result = result_queue.get()  # This will block until a result is available
            private_key, eoa_address, nonce, contract_address = result
            elapsed_time = time.time() - start_time
            print(f"\nMatch found after {total_guesses.value} guesses and {elapsed_time:.2f} seconds!")
            print(f"Private Key: 0x{private_key.hex()}")
            print(f"EOA Address: {eoa_address}")
            print(f"Nonce: {nonce}")
            print(f"Contract Address: 0x{contract_address}")
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
    print(f"Searching for deployer EOA to deploy contract address like: 0x{prefix}...{suffix}")
    print(f"Matching case: {match_case}")
    print(f"Checking up to nonce {max_nonce}")
    print(f"Using {num_processes} worker processes (+1 for logging).")
    print("Press Ctrl+C to stop the program")
    print("---")
    
    main(prefix, suffix, max_nonce, match_case, num_processes)