#define _WIN32_WINNT 0x0500   
#include <windows.h>   
#include <winnt.h>   
#include <winbase.h>   
#include <stdio.h>   

typedef struct _IMPINFO
{
    DWORD Magic;
    DWORD Magicu;

    DWORD Initialized;

    DWORD Entry;
    HMODULE Module;

    DWORD DllFlag;
    DWORD TlsEnable;

    DWORD HeaderSum;
    DWORD CodeSum;
    DWORD FileSum;

    LONGLONG TlsTime;
    LONGLONG EntryTime;

    DWORD TTThreshold;
    DWORD ETThreshold;
    DWORD TETThreshold;

    DWORD ImportAddress;
    DWORD ImportSize;

    DWORD IATAddress;
    DWORD IATSize;

    DWORD ResAddress;
    DWORD ResSize;

    DWORD TlsAddress;
    DWORD TlsSize;

    DWORD RelocAddress;
    DWORD RelocSize;

}IMPINFO, * PIMPINFO;

unsigned int crc32(unsigned char* ptr, unsigned int len)
{
    unsigned char i;
    unsigned int crc = 0;
    while (len-- != 0)
    {
        for (i = 0x80; i != 0; i /= 2)
        {
            if ((crc & 0x8000) != 0)
            {
                crc *= 2;
                crc ^= 0x1021;
            }
            else
                crc *= 2;
            if ((*ptr & i) != 0)
                crc ^= 0x1021;
        }
        ptr++;
    }
    return(crc);
}

unsigned char crc8(unsigned char* ptr, unsigned int len)
{
    unsigned char i;
    unsigned char crc = 0;
    while (len-- != 0) {
        for (i = 1; i != 0; i *= 2) {
            if ((crc & 1) != 0) {
                crc /= 2;
                crc ^= 0x8C;
            }
            else crc /= 2;
            if ((*ptr & i) != 0) crc ^= 0x8C;
        } ptr++;
    }
    return crc;
}

unsigned short crc16(unsigned char* ptr, unsigned int len) {

    unsigned char i;
    unsigned long crc = NULL;
    while (len--)
    {
        for (i = 0x80; i != 0; i = i >> 1)
        {
            crc = crc * 2;
            if ((crc & 0x10000) != 0)
            {
                crc = crc ^ 0x11021;
            }
            if ((*ptr & i) != 0)
            {
                crc = crc ^ (0x10000 ^ 0x11021);
            }
        } ptr++;
    }

    return crc;
}

PUCHAR EncryptData(PUCHAR szRec, ULONG nLen, UCHAR key)
{
    PUCHAR p = szRec;
    UCHAR PrvChar = 0;
    for (ULONG i = 0; i < nLen; i++)
    {
        UCHAR _t = *p;
        *p ^= key ^ crc8(&PrvChar, 1);
        *p -= key | i >> 2;
        PrvChar = _t | i | key;
        p++;
    }

    return szRec;
}

PUCHAR DecryptData(PUCHAR szRec, ULONG nLen, UCHAR key)
{
    PUCHAR p = szRec;
    UCHAR PrvChar = 0;
    for (ULONG i = 0; i < nLen; i++)
    {
        *p += key | i >> 2;
        *p ^= key ^ crc8(&PrvChar, 1);
        PrvChar = *p | i | key;
        p++;
    }

    return szRec;
}
int SEU_RandEx(int min, int max)
{
    if (min == max)
        return min;

    srand(GetTickCount());
    int seed = rand() + 3;

    return seed % (max - min + 1) + min;
}
PCHAR RandStr(PCHAR buf, int min, int max)
{

    int len = SEU_RandEx(min, max);

    //printf("Len:%d\n",len);   

    for (int i = 0; i < len; i++)
    {

        buf[i] = ((CHAR)(rand() % 26)) + 1;
        //printf("Rand: %x\n",buf[i]);   
    }

    buf[len] = 0;

    return buf;
}

BOOL FileOpenName(HWND hwnd, PCHAR FileName)
{
    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ZeroMemory(FileName, MAX_PATH);
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = (LPCWSTR)"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0\0";
    ofn.lpstrFile = (LPWSTR)FileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = (LPCWSTR)"exe";
    ofn.lpstrTitle = (LPCWSTR)"aaaaaa";

    ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;

    if (GetOpenFileName(&ofn))
        return TRUE;

    return FALSE;
}

DWORD RVA2Offset(PIMAGE_DOS_HEADER DosHeader, DWORD RVA)
{
    IMAGE_DOS_HEADER* mz_header = (IMAGE_DOS_HEADER*)DosHeader;
    IMAGE_NT_HEADERS* pe_header = (IMAGE_NT_HEADERS*)((DWORD)mz_header + (DWORD)mz_header->e_lfanew);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pe_header);
    for (int i = 0; i < pe_header->FileHeader.NumberOfSections; i++, section++)
    {
        if (section->VirtualAddress && section->SizeOfRawData)
        {
            if (RVA >= section->VirtualAddress && RVA <= section->VirtualAddress + section->SizeOfRawData)
                return section->PointerToRawData + (RVA - section->VirtualAddress);
        }
    }
    return 0;
}
PVOID SearchIMProtector(PVOID addr, DWORD size)
{
    DWORD* buffer = (DWORD*)addr;
    __try {

        for (int i = 2; i < (size - sizeof(IMPINFO)); i++)
        {
            if (buffer[i] == 0x217A4154 && buffer[i + 1] == 0x54417A21)
                return &buffer[i];
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {

        return 0;
    }

    return 0;
}
BOOL ScanOrgImportTable(PIMAGE_DOS_HEADER DosHeader, DWORD FileSize)
{
    PIMAGE_NT_HEADERS PeHeader = (PIMAGE_NT_HEADERS)((DWORD)DosHeader + DosHeader->e_lfanew);
    DWORD import_rva = (DWORD)PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)DosHeader + RVA2Offset(DosHeader, import_rva));

    PIMPINFO IMPer = (PIMPINFO)SearchIMProtector(DosHeader, FileSize);
    if (!IMPer || !IMPer->Entry)
    {
        printf("No IMPer Flag!\n");
        return 0;
    }
    printf("------Begin----IMProtecting-------------------\n\n");
    while (import_descriptor->OriginalFirstThunk && import_descriptor->Name && import_descriptor->FirstThunk)
    {
        IMAGE_THUNK_DATA* OrgFirstThunk = (IMAGE_THUNK_DATA*)((DWORD)DosHeader + RVA2Offset(DosHeader, (DWORD)import_descriptor->OriginalFirstThunk));
        IMAGE_THUNK_DATA* FirstThunk = (IMAGE_THUNK_DATA*)((DWORD)DosHeader + RVA2Offset(DosHeader, (DWORD)import_descriptor->FirstThunk));

        PCHAR DllName = (char*)((DWORD)DosHeader + RVA2Offset(DosHeader, (DWORD)import_descriptor->Name));
        printf("\nDllName: %s\nOrgFirstThunk: %x\tFirstThunk: %x\n", DllName, OrgFirstThunk, FirstThunk);

        while (OrgFirstThunk->u1.Ordinal)
        {
            if (OrgFirstThunk->u1.Ordinal & 0x80000000)
            {
                DWORD key = crc8((PUCHAR)&OrgFirstThunk->u1.Ordinal, 2);
                DWORD Ordinal = 0x80000000 | key << 16 | ((WORD)(OrgFirstThunk->u1.Ordinal & 0x0000FFFF) ^ (WORD)(key | (key << 8)));
                printf("----Ordinal[%X]: %x:%d\n", Ordinal, OrgFirstThunk->u1.Ordinal);
                OrgFirstThunk->u1.Ordinal = Ordinal;
                FirstThunk->u1.Ordinal = 0;

            }
            else {

                PCHAR FuncName = (char*)((DWORD)DosHeader + RVA2Offset(DosHeader, (DWORD)OrgFirstThunk->u1.AddressOfData));
                
                printf("----Name[%X]: %s\n", crc32((PUCHAR)FuncName, strlen(FuncName)), FuncName);
                OrgFirstThunk->u1.Ordinal = crc32((PUCHAR)FuncName, strlen(FuncName));
                RandStr(FuncName, strlen(FuncName), strlen(FuncName));
                FirstThunk->u1.Ordinal = 0;
            }
            FirstThunk++;
            OrgFirstThunk++;
        }

        import_descriptor++;
    }
    printf("-------End---Import(Address)Table---------------------\n\n");
    IMPer->Magic = 0;
    IMPer->Magicu = 0;

    IMPer->ImportAddress = PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    IMPer->ImportSize = PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    IMPer->IATAddress = PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
    IMPer->IATSize = PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

    IMPer->RelocAddress = PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    IMPer->RelocSize = PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
    PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

    PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
    PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;

    DWORD IMP_EP_RVA = IMPer->Entry - PeHeader->OptionalHeader.ImageBase;
    DWORD PE_EP_RVA = PeHeader->OptionalHeader.AddressOfEntryPoint;

    printf("PE_EP_RVA:%X\tIMP_Entry: %X\n", PE_EP_RVA, IMP_EP_RVA);

    PeHeader->OptionalHeader.AddressOfEntryPoint = IMP_EP_RVA;
    IMPer->Entry = PeHeader->OptionalHeader.ImageBase + PE_EP_RVA;

    IMPer->HeaderSum = crc32((PUCHAR)DosHeader, (ULONG)PeHeader->OptionalHeader.SizeOfHeaders);

    PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
    PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;

    printf("Headers[%X] Hash: %X\n", PeHeader->OptionalHeader.SizeOfHeaders, IMPer->HeaderSum);

    return true;
}
BOOL MappedPEFileAndScanImportTable(char* FilePath)
{

    if (GetFileAttributes((LPCWSTR)FilePath) == 0xFFFFFFFF)
        return FALSE;

    HANDLE hFile = CreateFile((LPCWSTR)FilePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    DWORD FileSize = GetFileSize(hFile, 0);

    if (FileSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))
    {
        CloseHandle(hFile);
        return FALSE;
    }

    HANDLE hMMFile = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);

    if (hMMFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        return FALSE;
    }

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)MapViewOfFile(hMMFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    if (!DosHeader) {

        CloseHandle(hMMFile);
        CloseHandle(hFile);
        return FALSE;

    }

    __try {

        if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
        {

            PIMAGE_NT_HEADERS PeHeader = (PIMAGE_NT_HEADERS)((DWORD)DosHeader + DosHeader->e_lfanew);

            if (PeHeader->Signature == IMAGE_NT_SIGNATURE)
            {

                if (PeHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
                {

                    if (PeHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE
                        && !(PeHeader->FileHeader.Characteristics & IMAGE_FILE_DLL))
                    {

                        if (PeHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                        {

                            if (PeHeader->OptionalHeader.AddressOfEntryPoint)
                            {

                                if (PeHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI
                                    || PeHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
                                {

                                    DWORD ret = ScanOrgImportTable(DosHeader, FileSize);

                                    UnmapViewOfFile(DosHeader);
                                    CloseHandle(hMMFile);
                                    CloseHandle(hFile);
                                    return ret;

                                }

                            }

                        }

                    }
                }
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {

        UnmapViewOfFile(DosHeader);
        CloseHandle(hMMFile);
        CloseHandle(hFile);
        return FALSE;
    }

    UnmapViewOfFile(DosHeader);
    CloseHandle(hMMFile);
    CloseHandle(hFile);
    return FALSE;
}
////////////////////////////////////////////////////////////////////////////////////   
int main()
{
    char FileName[MAX_PATH] = "C:\\Users\\malpwn\\Downloads\\puty.exe";
    if (FileOpenName(0, FileName))
    {
        if (MappedPEFileAndScanImportTable(FileName))
            printf("IMP success!");
        else printf("IMP failed!");
        getchar();
    }
    return 0;
}
