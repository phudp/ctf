import lief

# Create a new ELF binary
binary = lief.ELF.Binary("flag_elf", lief.ELF.ELF_CLASS.CLASS64)
binary.header.file_type = lief.ELF.E_TYPE.EXECUTABLE
binary.header.machine_type = lief.ELF.ARCH.x86_64
binary.header.identity_os_abi = lief.ELF.OS_ABI.SYSTEMV

# Create a .text section
text_section = lief.ELF.Section(".text")
text_section.type = lief.ELF.SECTION_TYPES.PROGBITS
text_section.flags = lief.ELF.SECTION_FLAGS.EXECINSTR | lief.ELF.SECTION_FLAGS.ALLOC
text_section.alignment = 0x10
text_section.content = [
    0xB8, 0x3C, 0x00, 0x00, 0x00,   # mov eax, 60 (exit syscall)
    0xBF, 0x00, 0x00, 0x00, 0x00,   # mov edi, 0
    0x0F, 0x05                      # syscall
]
binary.add(text_section)

# Set entry point
binary.entrypoint = text_section.virtual_address

# Create a DWARF line program spoof: tell GDB the source file is /app/flag.txt
src_path = "/app/flag.txt"
binary.add_source(src_path)

# Write ELF to disk
output_path = "fake_flag.elf"
binary.write(output_path)

print(f"[*] ELF created: {output_path}")
