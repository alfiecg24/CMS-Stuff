#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct __BlobIndex {
	uint32_t type;
	uint32_t offset;
} CS_BlobIndex;

typedef struct __SuperBlob {
	uint32_t magic;
	uint32_t length;
	uint32_t count;
	CS_BlobIndex index[];
} CS_SuperBlob;

typedef struct __CodeDirectory {
	uint32_t magic;
	uint32_t length;
	uint32_t version;
	uint32_t flags;
	uint32_t hashOffset;
	uint32_t identOffset;
	uint32_t nSpecialSlots;
	uint32_t nCodeSlots;
	uint32_t codeLimit;
	uint8_t hashSize;
	uint8_t hashType;
	uint8_t spare1;
	uint8_t	pageSize;
	uint32_t spare2;
} CS_CodeDirectory;

enum {
    CSBLOB_REQUIREMENT = 0xfade0c00,
    CSBLOB_REQUIREMENTS = 0xfade0c01,
    CSBLOB_CODEDIRECTORY = 0xfade0c02,
    CSBLOB_EMBEDDED_SIGNATURE = 0xfade0cc0,
    CSBLOB_DETACHED_SIGNATURE = 0xfade0cc1,
    CSBLOB_ENTITLEMENTS = 0xfade7171,
    CSBLOB_DER_ENTITLEMENTS = 0xfade7172,
    CSBLOB_SIGNATURE_BLOB = 0xfade0b01
} CS_BlobType;

void extractSignatureBlob(int offset, uint8_t *dataSource, size_t signatureBlobLen, uint8_t **dataDestination) {
    // Go to offset in data source
    uint8_t *data = dataSource + offset;
    uint8_t *newData = malloc(signatureBlobLen);
    size_t newDataSize = 0;
    memcpy(newData, data, signatureBlobLen);
    *dataDestination = newData;
}

int main(int argc, char *argv[]) {
    
    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }

    FILE *cmsFile = fopen(argv[1], "rb");
    if (cmsFile == NULL) {
        printf("Error: Could not open file %s\n", argv[1]);
        return 1;
    }

    fseek(cmsFile, 0, SEEK_END);
    size_t cmsFileSize = ftell(cmsFile);
    fseek(cmsFile, 0, SEEK_SET);

    uint8_t *cmsFileData = malloc(cmsFileSize);
    fread(cmsFileData, 1, cmsFileSize, cmsFile);
    fclose(cmsFile);

    CS_SuperBlob *superBlob = (CS_SuperBlob *)cmsFileData;
    uint8_t magic = *(uint8_t *)cmsFileData;
    superBlob->magic = ntohl(superBlob->magic);
    superBlob->length = ntohl(superBlob->length);
    superBlob->count = ntohl(superBlob->count);
    for (int i = 0; i < superBlob->count; i++) {
        superBlob->index[i].type = ntohl(superBlob->index[i].type);
        superBlob->index[i].offset = ntohl(superBlob->index[i].offset);
    }
    if (superBlob->magic != CSBLOB_EMBEDDED_SIGNATURE) {
        printf("Error: Invalid magic number, 0x%x\n", superBlob->magic);
        printf("Please make sure the file is a CMS file, it should start with the magic 0xFADE0CC0\n");
        return 1;
    }

    printf("Magic: 0x%X\n", superBlob->magic);
    printf("Length: 0x%X\n", superBlob->length);
    printf("Number of blobs: %u\n", superBlob->count);
    for (int i = 0; i < superBlob->count; i++) {

        printf("\nBlob %d:\n", i + 1);
        printf("  Type: 0x%X\n", superBlob->index[i].type);
        printf("  Offset: 0x%X\n", superBlob->index[i].offset);

        if (superBlob->index[i].offset > cmsFileSize) {
            printf("Error: Blob offset is out of bounds\n");
            return 1;
        }
        size_t len;
        if (i == superBlob->count - 1) {
            len = cmsFileSize - superBlob->index[i].offset;
        }
        else {
            len = superBlob->index[i + 1].offset - superBlob->index[i].offset;
        }
        printf("    Length: 0x%zX\n", len);
        
        uint32_t magic = ntohl(*(uint32_t *)(cmsFileData + superBlob->index[i].offset));
        if (magic == CSBLOB_REQUIREMENT) {
            printf("  Requirement blob\n");
        }
        else if (magic == CSBLOB_REQUIREMENTS) {
            printf("  Requirements blob\n");
        }
        else if (magic == CSBLOB_CODEDIRECTORY) {
            printf("  Code directory blob\n");
            CS_CodeDirectory *codeDirectory = (CS_CodeDirectory *)(cmsFileData + superBlob->index[i].offset);
            codeDirectory->magic = ntohl(codeDirectory->magic);
            codeDirectory->length = ntohl(codeDirectory->length);
            codeDirectory->version = ntohl(codeDirectory->version);
            codeDirectory->flags = ntohl(codeDirectory->flags);
            codeDirectory->hashOffset = ntohl(codeDirectory->hashOffset);
            codeDirectory->identOffset = ntohl(codeDirectory->identOffset);
            codeDirectory->nSpecialSlots = ntohl(codeDirectory->nSpecialSlots);
            codeDirectory->nCodeSlots = ntohl(codeDirectory->nCodeSlots);
            codeDirectory->codeLimit = ntohl(codeDirectory->codeLimit);
            codeDirectory->hashSize = ntohl(codeDirectory->hashSize);
            codeDirectory->hashType = ntohl(codeDirectory->hashType);
            codeDirectory->spare1 = ntohl(codeDirectory->spare1);
            codeDirectory->pageSize = ntohl(codeDirectory->pageSize);
            codeDirectory->spare2 = ntohl(codeDirectory->spare2);
            printf("    Magic: 0x%X\n", codeDirectory->magic);
            printf("    Length: 0x%X\n", codeDirectory->length);
            printf("    Version: 0x%X\n", codeDirectory->version);
            printf("    Flags: 0x%X\n", codeDirectory->flags);
            printf("    Hash offset: 0x%X\n", codeDirectory->hashOffset);
            printf("    Identifier offset: 0x%X\n", codeDirectory->identOffset);
            printf("    Number of special slots: %u\n", codeDirectory->nSpecialSlots);
            printf("    Number of code slots: %u\n", codeDirectory->nCodeSlots);
            printf("    Code limit: 0x%X\n", codeDirectory->codeLimit);
            printf("    Hash size: 0x%X\n", codeDirectory->hashSize);
            printf("    Hash type: 0x%X\n", codeDirectory->hashType);
            printf("    Spare 1: %u\n", codeDirectory->spare1);
            printf("    Page size: 0x%X\n", codeDirectory->pageSize);
            printf("    Spare 2: %u\n", codeDirectory->spare2);
        }
        else if (magic == CSBLOB_EMBEDDED_SIGNATURE) {
            printf("  Embedded signature blob\n");
        }
        else if (magic == CSBLOB_DETACHED_SIGNATURE) {
            printf("  Detached signature blob\n");
        }
        else if (magic == CSBLOB_ENTITLEMENTS) {
            printf("  Entitlements blob\n");
        }
        else if (magic == CSBLOB_DER_ENTITLEMENTS) {
            printf("  DER entitlements blob\n");
        }
        else if (magic == CSBLOB_SIGNATURE_BLOB) {
            printf("  Signature blob\n");
            uint8_t *data;
            extractSignatureBlob(superBlob->index[i].offset, cmsFileData, len, &data);
            char *fileName = malloc(strlen(argv[1]) + 1 + 15);
            strcpy(fileName, argv[1]);
            strcat(fileName, "_SignatureBlob");
            FILE *signatureFile = fopen(fileName, "wb");
            fwrite(data, 1, len, signatureFile);
            fclose(signatureFile);
            free(data);
        }
        else {
            printf("  Unknown blob type\n");
        }
    }

    free(cmsFileData);
    
    
    return 0;
}