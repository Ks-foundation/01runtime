#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#include <stdint.h>

#define ELF_MAGIC "\x7fELF"
#define PE_MAGIC "MZ"

typedef struct {
    uint64_t virtual_address;
    uint64_t offset;
    uint64_t size;
} SectionHeader;

// Define the entry point of the program
int main(int argc, char *argv[]) {
    // Check if the user provided the correct number of arguments
    if (argc != 2) {
        printf("Usage: %s <binary_file>\n", argv[0]);
        return 1; // Return error code
    }

    // Open the binary file provided by the user
    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        perror("Error opening file");
        return 1; // Return error code
    }

    // Read the magic bytes to determine the format
    char magic[4];
    if (read(fd, magic, sizeof(magic)) != sizeof(magic)) {
        perror("Error reading file");
        close(fd);
        return 1; // Return error code
    }

    // Seek back to the beginning of the file
    lseek(fd, 0, SEEK_SET);

    // Check if the file is ELF format
    if (memcmp(magic, ELF_MAGIC, sizeof(magic)) == 0) {
        // ELF format detected
        printf("ELF format detected, loading ELF file...\n");

        // Read ELF header
        Elf64_Ehdr elf_header;
        if (read(fd, &elf_header, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
            perror("Error reading ELF header");
            close(fd);
            return 1; // Return error code
        }

        // Read section headers
        SectionHeader *section_headers = malloc(sizeof(SectionHeader) * elf_header.e_shnum);
        if (section_headers == NULL) {
            perror("Error allocating memory for section headers");
            close(fd);
            return 1; // Return error code
        }
        lseek(fd, elf_header.e_shoff, SEEK_SET);
        if (read(fd, section_headers, sizeof(SectionHeader) * elf_header.e_shnum) !=
            sizeof(SectionHeader) * elf_header.e_shnum) {
            perror("Error reading section headers");
            free(section_headers);
            close(fd);
            return 1; // Return error code
        }

        // Map each loadable segment into memory
        for (int i = 0; i < elf_header.e_shnum; ++i) {
            if (section_headers[i].size > 0 && (section_headers[i].virtual_address != 0 || section_headers[i].offset != 0)) {
                void *segment_addr = mmap((void *)section_headers[i].virtual_address,
                                          section_headers[i].size,
                                          PROT_READ | PROT_WRITE | PROT_EXEC,
                                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                          -1, 0);
                if (segment_addr == MAP_FAILED) {
                    perror("Error mapping segment into memory");
                    free(section_headers);
                    close(fd);
                    return 1; // Return error code
                }
                lseek(fd, section_headers[i].offset, SEEK_SET);
                if (read(fd, segment_addr, section_headers[i].size) != section_headers[i].size) {
                    perror("Error reading segment from file");
                    free(section_headers);
                    close(fd);
                    return 1; // Return error code
                }
            }
        }

        // Free allocated memory and close file descriptor
        free(section_headers);
        close(fd);

        // Jump to the entry point of the ELF binary and execute it
        void (*elf_entry)() = (void (*)())elf_header.e_entry;
        elf_entry();
    }
    // Check if the file is PE COFF or PE format
    else if (memcmp(magic, PE_MAGIC, sizeof(magic)) == 0) {
        // PE COFF or PE format detected
        printf("PE COFF or PE format detected, loading PE file...\n");

        // Read the DOS header to determine the format
        char dos_magic[2];
        if (read(fd, dos_magic, sizeof(dos_magic)) != sizeof(dos_magic)) {
            perror("Error reading DOS header");
            close(fd);
            return 1; // Return error code
        }

        // Seek back to the beginning of the file
        lseek(fd, 0, SEEK_SET);

        // PE COFF format
        if (dos_magic[0] == 'M' && dos_magic[1] == 'Z') {
            printf("PE COFF format detected, loading PE COFF file...\n");
            // Add PE COFF loading logic here
        }
        // PE format
        else {
            printf("PE format detected, loading PE file...\n");
            // Add PE loading logic here
        }
    }
    else {
        printf("Unsupported binary format\n");
        close(fd);
        return 1; // Return error code
    }

    return 0; // Return success code
}
