﻿#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

void print_header(const char name[], int indent) {
    for (int i = 0; i < indent; i++) {
        printf("\t");
    }
    printf("%s\n", name);
}

void print_word(const char name[], int data) {
    printf("\t%-25s\t%9x\n", name, data);
}

void parse_dos_header(IMAGE_DOS_HEADER* dh, FILE* fp) {
    // File reading
    fseek(fp, 0x00, SEEK_SET);
    size_t readed = fread(dh, 1, sizeof(*dh), fp);
    // Printing DOS-HEADER
    print_header("[DOS-HEADER]", 0);
    print_word("e_magic", dh->e_magic);
    print_word("e_cblp", dh->e_cblp);
    print_word("e_cp", dh->e_cp);
    print_word("e_crlc", dh->e_crlc);
    print_word("e_cparhdr", dh->e_cparhdr);
    print_word("e_minalloc", dh->e_minalloc);
    print_word("e_maxalloc", dh->e_maxalloc);
    print_word("e_ss", dh->e_ss);
    print_word("e_sp", dh->e_sp);
    print_word("e_csum", dh->e_csum);
    print_word("e_ip", dh->e_ip);
    print_word("e_cs", dh->e_cs);
    print_word("e_lfarlc", dh->e_lfarlc);
    print_word("e_ovno", dh->e_ovno);
    print_word("e_res", *dh->e_res); //array
    print_word("e_oemid", dh->e_oemid);
    print_word("e_oeminfo", dh->e_oeminfo);
    print_word("e_res2", *dh->e_res2); //array
    print_word("e_lfanew", dh->e_lfanew);
    printf("\n");
}

void print_file_header(IMAGE_FILE_HEADER* fh, int offset) {
    print_header("[FILE-HEADER]", 1);
    print_word("machine", fh->Machine);
    print_word("number_of_sections", fh->NumberOfSections);
    print_word("time_date_stamp", fh->TimeDateStamp);
    print_word("pointer_to_symbol_table", fh->PointerToSymbolTable);
    print_word("number_of_symbols", fh->NumberOfSymbols);
    print_word("size_of_optional_header", fh->SizeOfOptionalHeader);
    print_word("characteristics", fh->Characteristics);
}
void print_optional_header(IMAGE_OPTIONAL_HEADER32* oh) {
    print_header("[OPTIONAL-HEADER]", 1);
    print_word("Magic",oh->Magic);
    print_word("MajorLinkerVersion",oh->MajorLinkerVersion);
    print_word("MinorLinkerVersion", oh->MinorLinkerVersion);
    print_word("SizeOfCode", oh->SizeOfCode);
    print_word("SizeOfInitializedData", oh->SizeOfInitializedData);
    print_word("SizeOfUninitializedData", oh->SizeOfUninitializedData);
    print_word("AddressOfEntryPoint", oh->AddressOfEntryPoint);
    print_word("BaseOfCode", oh->BaseOfCode);
    print_word("BaseOfData", oh->BaseOfData);
    print_word("ImageBase", oh->ImageBase);
    print_word("SectionAlignment", oh->SectionAlignment);
    print_word("FileAlignment", oh->FileAlignment);
    print_word("MajorOperatingSystemVersion", oh->MajorOperatingSystemVersion);
    print_word("MinorOperatingSystemVersion", oh->MinorOperatingSystemVersion);
    print_word("MajorImageVersion", oh->MajorImageVersion);
    print_word("MinorImageVersion", oh->MinorImageVersion);
    print_word("MajorSubsystemVersion", oh->MajorSubsystemVersion);
    print_word("MinorSubsystemVersion", oh->MinorSubsystemVersion);
    print_word("Win32VersionValue", oh->Win32VersionValue);
    print_word("SizeOfImage", oh->SizeOfImage);
    print_word("SizeOfHeaders", oh->SizeOfHeaders);
    print_word("CheckSum", oh->CheckSum);
    print_word("Subsystem", oh->Subsystem);
    print_word("DllCharacteristics", oh->DllCharacteristics);
    print_word("SizeOfStackReserve", oh->SizeOfStackReserve);
    print_word("SizeOfStackCommit", oh->SizeOfStackCommit);
    print_word("SizeOfHeapReserve", oh->SizeOfHeapReserve);
    print_word("SizeOfHeapCommit", oh->SizeOfHeapCommit);
    print_word("LoaderFlags", oh->LoaderFlags);
    print_word("NumberOfRvaAndSizes", oh->NumberOfRvaAndSizes);
    /*
    * El siguiente es un arreglo de estructuras, hay que imprimirlo recorriendolo
    * IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    */
    printf("\t%-25s\n", "DataDirectory");
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        IMAGE_DATA_DIRECTORY *idd = &oh->DataDirectory[i];
        printf("\t[%d]\t%-25s\t%9x\n", i, "VirtualAddress", idd->VirtualAddress);
        printf("\t\t%-25s\t%9x\n", "Size", idd->Size);
    }
    /*
    * Se podría incorporar una escritura explicita de las posiciones 1 y 2
    * correspondientes a los directorios de Import y Export
    */

}

void parse_nt_header(IMAGE_NT_HEADERS32* nth, FILE* fp, int offset) {
    // File reading
    fseek(fp, offset, SEEK_SET); // En este punto se corta
    size_t readed = fread(nth, 1, sizeof(*nth), fp);
    // Printing NT-HEADER
    print_header("[NT-HEADER]", 0);
    print_word("Signature", nth->Signature);
    int file_header_offset = offset + 4;
    print_file_header(&nth->FileHeader, file_header_offset);
    print_optional_header(&nth->OptionalHeader);
    printf("\n");
}

IMAGE_SECTION_HEADER* parse_section_headers(IMAGE_SECTION_HEADER* sh, FILE* fp, int offset, int section_size, int number_of_sections, int import_directory_rva) {
    print_header("[SECTION-HEADERS]", 0);
    IMAGE_SECTION_HEADER* import_section = NULL;
    // print section data
    for (int i = 0; i < number_of_sections; i++) {
        fseek(fp, offset, SEEK_SET);
        size_t readed = fread(sh, 1, sizeof(*sh), fp);
        printf("\t%s\n", sh->Name);
        print_word("Virtual Size", (int) sh->Misc.VirtualSize);
        print_word("Virtual Address", sh->VirtualAddress);
        print_word("Size Of Raw Data", sh->SizeOfRawData);
        print_word("Pointer To Raw Data", sh->PointerToRawData);
        print_word("Pointer To Relocations", sh->PointerToRelocations);
        print_word("Pointer To Line Numbers", sh->PointerToLinenumbers);
        print_word("Number Of Relocations", sh->NumberOfRelocations);
        print_word("Number Of Line Numbers", sh->NumberOfLinenumbers);
        print_word("Characteristics", sh->Characteristics);
        printf("\n");
        // save section that contains import directory table
        if (import_directory_rva >= sh->VirtualAddress && import_directory_rva < sh->VirtualAddress + sh->Misc.VirtualSize) {
            import_section = sh;
        }
        offset = offset + section_size;
        
    }
    return import_section;
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

int main() {
    // Variable definition
    FILE* fp;
    IMAGE_DOS_HEADER* dh = (IMAGE_DOS_HEADER*) malloc(sizeof(IMAGE_DOS_HEADER));
    IMAGE_NT_HEADERS32* nth = (IMAGE_NT_HEADERS32 *) malloc(sizeof(IMAGE_NT_HEADERS32));
    IMAGE_SECTION_HEADER* sh = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
    char file_name[255];

    // Get file name
    printf("Enter file name: ");
    fgets(file_name, sizeof(file_name), stdin);
    newLineRemover(file_name);

    // Open file
    fp = fopen(file_name, "r");
    if (fp == NULL) {
        printf("File Open error\nAborting\n");
        return -1;
    }
    printf("%s\t%d\n",file_name, (int) fp);

    // Parse DOS-HEADER
    parse_dos_header(dh, fp);

    // Parse NT-HEADER
    int nt_header_offset = (int) dh->e_lfanew;
    parse_nt_header(nth, fp, nt_header_offset);
    int import_directory_rva = nth->OptionalHeader.DataDirectory[1].VirtualAddress;
    printf("Import directory RVA: %x", import_directory_rva);

    // Parse SECTION-HEADERS
    int s_header_offset = (DWORD) nt_header_offset + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD) nth->FileHeader.SizeOfOptionalHeader;
    int section_size = (DWORD)sizeof(IMAGE_SECTION_HEADER);
    int number_of_sections = nth->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* import_section;
    import_section = parse_section_headers(sh, fp, s_header_offset, section_size, number_of_sections, import_directory_rva);
    printf("IMPORT SECTION AT: %x", import_section);
    int import_table_offset = import_section->PointerToRawData;
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(import_table_offset + (import_directory_rva - import_section->VirtualAddress));
    
    printf("\n******* DLL IMPORTS *******\n");
    for (; import_descriptor->Name != 0; import_descriptor++) {
        // imported dll modules
        printf("\t%s\n", import_table_offset + (import_descriptor->Name - import_section->VirtualAddress));
        int thunk = import_descriptor->OriginalFirstThunk == 0 ? import_descriptor->FirstThunk : import_descriptor->OriginalFirstThunk;
        PIMAGE_THUNK_DATA thunk_data = (PIMAGE_THUNK_DATA)(import_table_offset + (thunk - import_section->VirtualAddress));

        // dll exported functions
        for (; thunk_data->u1.AddressOfData != 0; thunk_data++) {
            //a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯
            if (thunk_data->u1.AddressOfData > 0x80000000) {
                //show lower bits of the value to get the ordinal ¯\_(ツ)_/¯
                printf("\t\tOrdinal: %x\n", (WORD)thunk_data->u1.AddressOfData);
            }
            else {
                printf("\t\t%s\n", (import_table_offset + (thunk_data->u1.AddressOfData - import_section->VirtualAddress + 2)));
            }
        }
    }
    



    // Close the file and exit
    fclose(fp);
    return 0;
}





