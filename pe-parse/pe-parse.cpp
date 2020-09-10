#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

struct FILE_HEADER {
    WORD machine;
    WORD number_of_sections;
    DWORD time_date_stamp;
    DWORD pointer_to_symbol_table;
    DWORD number_of_symbols;
    WORD size_of_optional_header;
    WORD characteristics;
};
typedef struct FILE_HEADER FILE_HEADER;

void parse_dos_header(IMAGE_DOS_HEADER* dh, FILE* fp);
void parse_nt_header(IMAGE_NT_HEADERS32* nth, FILE* fp, int offset);
void parse_file_header(struct FILE_HEADER* fh, FILE* fp, int offset);
void newLineRemover(char* array);

int main() {
    // Variable definition
    FILE* fp;
    IMAGE_DOS_HEADER* dh = (IMAGE_DOS_HEADER*) malloc(sizeof(IMAGE_DOS_HEADER));
    IMAGE_NT_HEADERS32* nth = (IMAGE_NT_HEADERS32 *) malloc(sizeof(IMAGE_NT_HEADERS32));
    FILE_HEADER* fh = (FILE_HEADER *) malloc(sizeof(FILE_HEADER));
    char file_name[255];

    // Get file name
    printf("Enter file name: ");
    fgets(file_name, sizeof(file_name), stdin);
    newLineRemover(file_name);

    // Open file
    fp = fopen(file_name, "r");

    // Parse DOS-HEADER
    parse_dos_header(dh, fp);

    // Parse NT-HEADER
    int nt_header_offset = (int) dh->e_lfanew;
    parse_nt_header(nth, fp, nt_header_offset);

    // Parse FILE-HEADER
    int file_header_offset = nt_header_offset + 4;
    parse_file_header(fh, fp, file_header_offset);

    // Close the file and exit
    fclose(fp);
    return 0;
}

void newLineRemover(char* array) {
    int i, length;
    length = strlen(array);
    for (i = 0; i < length; i++)
    {
        if (array[i] == '\n')
            array[i] = '\0';
    }
}

void parse_dos_header(IMAGE_DOS_HEADER* dh, FILE* fp) {
    printf("[DOS-HEADER]\n");
    fseek(fp, 0x00, SEEK_SET);
    size_t readed = fread(dh, 1, sizeof(*dh), fp);
    printf("\te_magic: %x\n", dh->e_magic);
    printf("\te_cblp: %x\n", dh->e_cblp);
    printf("\te_cp: %x\n", dh->e_cp);
    printf("\te_crlc: %x\n", dh->e_crlc);
    printf("\te_cparhdr: %x\n", dh->e_cparhdr);
    printf("\te_minalloc: %x\n", dh->e_minalloc);
    printf("\te_maxalloc: %x\n", dh->e_maxalloc);
    printf("\te_ss: %x\n", dh->e_ss);
    printf("\te_sp: %x\n", dh->e_sp);
    printf("\te_csum: %x\n", dh->e_csum);
    printf("\te_ip: %x\n", dh->e_ip);
    printf("\te_cs: %x\n", dh->e_cs);
    printf("\te_lfarlc: %x\n", dh->e_lfarlc);
    printf("\te_ovno: %x\n", dh->e_ovno);
    printf("\te_res: %x\n", *dh->e_res); //array
    printf("\te_oemid: %x\n", dh->e_oemid);
    printf("\te_oeminfo: %x\n", dh->e_oeminfo);
    printf("\te_res2: %x\n", *dh->e_res2); //array
    printf("\te_lfanew: %x\n", dh->e_lfanew);
}

void parse_nt_header(IMAGE_NT_HEADERS32* nth, FILE* fp, int offset) {
    printf("[NT-HEADER]\tat %x\t size %d\n", offset, sizeof(*nth));
    fseek(fp, offset, SEEK_SET); // En este punto se corta
    size_t readed = fread(nth, 1, sizeof(*nth), fp);
    printf("\tSignature: %x\n", nth->Signature);
    printf("\tFile Header: %x\n", nth->FileHeader);
    printf("\tOptional Header: %x\n", nth->OptionalHeader);
}

void parse_file_header(struct FILE_HEADER* fh, FILE* fp, int offset) {
    printf("[FILE-HEADER] at %x\n", offset);
    fseek(fp, offset, SEEK_SET);
    size_t readed = fread(fh, 1, sizeof(*fh), fp);
    printf("\tmachine: %x\n", fh->machine);
    printf("\tnumber_of_sections: %x\n", fh->number_of_sections);
    printf("\ttime_date_stamp: %x\n", fh->time_date_stamp);
    printf("\tpointer_to_symbol_table: %x\n", fh->pointer_to_symbol_table);
    printf("\tnumber_of_symbols: %x\n", fh->number_of_symbols);
    printf("\tsize_of_optional_header: %x\n", fh->size_of_optional_header);
    printf("\tcharacteristics: %x\n", fh->characteristics);
}