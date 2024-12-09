def rotl(x, n):
    """Rotate left operation for 64-bit values."""
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

# Round constants for Keccak-f (24 rounds)
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

# Rho offsets
rho_offsets = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
]

def keccak_f(state):
    """Applies the Keccak-f permutation to the state."""
    for round_index in range(24):
        # Theta step
        C = [state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20] for i in range(5)]
        D = [(C[(i - 1) % 5] ^ rotl(C[(i + 1) % 5], 1)) for i in range(5)]
        for i in range(25):
            state[i] ^= D[i % 5]
        
        # Rho and Pi steps combined
        new_state = [0] * 25
        for x in range(5):
            for y in range(5):
                new_x, new_y = y, (2 * x + 3 * y) % 5
                new_state[new_y * 5 + new_x] = rotl(state[x * 5 + y], rho_offsets[x][y])
        state[:] = new_state  # Update state
        
        # Chi step
        for y in range(0, 25, 5):
            T = state[y:y + 5]
            for i in range(5):
                state[y + i] = T[i] ^ (~T[(i + 1) % 5] & T[(i + 2) % 5])
        
        # Iota step
        state[0] ^= RC[round_index]
    return state

def pad_message(message: bytes):
    """Pads the message to a multiple of the block size (1088 bits for SHA3-256)."""
    block_size = 136  # SHA3-256 block size is 1088 bits (136 bytes)
    message += b'\x06'  # Padding start delimiter
    padding_len = block_size - (len(message) % block_size) - 1
    message += b'\x00' * padding_len + b'\x80'  # Padding with zeros and ending with 0x80
    return message

def sha3_256(message: str) -> str:
    """Computes the SHA3-256 hash of the input message."""
    # Convert input to bytes and pad the message
    message_bytes = message.encode('utf-8')
    padded_message = pad_message(message_bytes)
    
    # Initialize the state (5x5 matrix of 64-bit words, flattened)
    state = [0] * 25
    
    # Absorption phase
    for i in range(0, len(padded_message), 136):
        block = padded_message[i:i + 136]
        for j in range(17):  # 136 bytes = 17 64-bit words
            word = int.from_bytes(block[j * 8: (j + 1) * 8], 'little')
            state[j] ^= word
        keccak_f(state)  # Apply Keccak-f permutation
    
    # Squeezing phase
    hash_output = b''
    for i in range(4):  # Extract 256 bits (32 bytes) from the first 4 state words
        hash_output += state[i].to_bytes(8, 'little')
    
    return hash_output[:32].hex()

# Example usage
if __name__ == "__main__":
    user_input = input("Enter something: ")
    hash_output = sha3_256(user_input)
    print(f"Input: {user_input}")
    print(f"SHA3-256 Hash: {hash_output}")
