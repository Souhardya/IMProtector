#include <windows.h>   
#include <stdio.h>   

#include "IMProtector.h"   

#pragma comment(linker, "/merge:.rdata=.data")   

#define IMP_DLL_FLAG                    0   
#define IMP_TLS_ENABLE                  1   
#define IMP_TLS_TIME_THRESHOLD          500000*5   
#define IMP_ENTRY_TIME_THRESHOLD        500000*10   
#define IMP_TLS2ENTRY_TIME_THRESHOLD    500000*5   

#define IMP_USDATA                      ((PKUSER_SHARED_DATA)0x7FFE0000)   

IMPINFO IMPer = {
    0x217A4154, 0x54417A21, 0, (DWORD)IMP_Entry, 0, IMP_DLL_FLAG, IMP_TLS_ENABLE, 0, 0, 0,
    0, 0, IMP_TLS_TIME_THRESHOLD,IMP_ENTRY_TIME_THRESHOLD,IMP_TLS2ENTRY_TIME_THRESHOLD,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

enum _IMP_NTAPI_INDEX {
    iNtQueryInformationThread,
    iNtQueryInformationProcess,
    iNtSetInformationThread,
    iNtSetInformationProcess,
    iNtQueryVirtualMemory,
    iNtProtectVirtualMemory,
    iNtTerminateThread,
};

DWORD IMP_NtApiIndex[] = { 0x1C0181C5, 0x10F31380, 0xCB2E430A, 0x3F3D258E, 0x71879C3E, 0x2D84705D, 0xF7545030, 0 };

PVOID IMP_DbgBreakPoint = (PVOID)0x02B8354C;
PVOID IMP_DbgUiRemoteBreakin = (PVOID)0x6BA6DBC8;
PVOID IMP_RtlIsCurrentThreadAttachExempt = (PVOID)0x8370D384;

PVOID IMP_LoadLibraryA = (PVOID)0xF17F6FFE;
PVOID IMP_RtlAllocateHeap = (PVOID)0xCFC43834;

#define IMP_LoadLibraryA(a) ((HMODULE (WINAPI*)(PCHAR))IMP_LoadLibraryA)(a)   
#define IMP_RtlAllocateHeap(a,b,c) ((PVOID(WINAPI*)(HANDLE,DWORD,DWORD))IMP_RtlAllocateHeap)(a,b,c)   

DWORD CRC32(BYTE* ptr, DWORD Size)
{

    DWORD crcTable[256], crcTmp1;


    for (int i = 0; i < 256; i++)
    {
        crcTmp1 = i;
        for (int j = 8; j > 0; j--)
        {
            if (crcTmp1 & 1) crcTmp1 = (crcTmp1 >> 1) ^ 0xEDB88320L;
            else crcTmp1 >>= 1;
        }

        crcTable[i] = crcTmp1;
    }

    DWORD crcTmp2 = 0xFFFFFFFF;
    while (Size--)
    {
        crcTmp2 = ((crcTmp2 >> 8) & 0x00FFFFFF) ^ crcTable[(crcTmp2 ^ (*ptr)) & 0xFF];
        ptr++;
    }

    return (crcTmp2 ^ 0xFFFFFFFF);
}



unsigned int IMP_CRC32(unsigned char* ptr, unsigned int len)
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

unsigned char IMP_CRC8(unsigned char* ptr, unsigned int len)
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
WCHAR IMP_towlower(WCHAR wc)
{
    return !(wc & 0xFF00) && (wc >= 'A') && (wc <= 'Z') ? (wc - (('A' - 'a'))) : wc;
}
int IMP_wcsicmp(const wchar_t* cs, const wchar_t* ct)
{
    while (IMP_towlower(*cs) == IMP_towlower(*ct))
    {
        if (*cs == 0)
            return 0;
        cs++;
        ct++;
    }
    return IMP_towlower(*cs) - IMP_towlower(*ct);
}
int IMP_strcmp(PCHAR s1, PCHAR s2)
{
    while (*s1 == *s2)
    {
        if (*s1 == 0)
            return 0;
        s1++;
        s2++;
    }
    return s1 - s2;
}

int IMP_strlen(PCHAR str)
{
    PCHAR p = str;
    while (*p++);
    return p - str - 1;
}

__declspec(naked) NT_TEB* IMP_GetCurrentTEB()
{
    __asm mov eax, fs: [18h]
        __asm retn
}

__declspec(naked)
NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS InformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength)
{
    __asm {
        MOV EAX, IMP_NtApiIndex[iNtQueryInformationProcess * 4]
        MOV EDX, 7FFE0300h
        CALL DWORD PTR DS : [EDX]
        RETN 14h
    }
}

__declspec(naked)
NTSTATUS NTAPI NtQueryInformationThread(
    HANDLE ThreadHandle,
    THREAD_INFORMATION_CLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength)
{
    __asm {
        MOV EAX, IMP_NtApiIndex[iNtQueryInformationThread * 4]
        MOV EDX, 7FFE0300h
        CALL DWORD PTR DS : [EDX]
        RETN 14h
    }
}
__declspec(naked)
NTSTATUS NTAPI NtSetInformationThread(
    HANDLE ThreadHandle,
    THREAD_INFORMATION_CLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength)
{
    __asm {
        MOV EAX, IMP_NtApiIndex[iNtSetInformationThread * 4]
        MOV EDX, 7FFE0300h
        CALL DWORD PTR DS : [EDX]
        RETN 10h
    }
}
__declspec(naked)
NTSTATUS NTAPI NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    DWORD* NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection)
{
    __asm {
        MOV EAX, IMP_NtApiIndex[iNtProtectVirtualMemory * 4]
        MOV EDX, 7FFE0300h
        CALL DWORD PTR DS : [EDX]
        RETN 14h
    }
}
__declspec(naked)
NTSTATUS NTAPI NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID Address,
    MEMORY_INFORMATION_CLASS VirtualMemoryInformationClass,
    PVOID VirtualMemoryInformation,
    DWORD Length,
    DWORD* ResultLength)
{
    __asm {
        MOV EAX, IMP_NtApiIndex[iNtQueryVirtualMemory * 4]
        MOV EDX, 7FFE0300h
        CALL DWORD PTR DS : [EDX]
        RETN 18h
    }
}
__declspec(naked)
NTSTATUS NTAPI NtTerminateThread(HANDLE hThread, DWORD ExitCode)
{
    __asm {
        MOV EAX, IMP_NtApiIndex[iNtTerminateThread * 4]
        MOV EDX, 7FFE0300h
        CALL DWORD PTR DS : [EDX]
        RETN 18h
    }
}

BOOL WINAPI IMP_VirtualProtect(PVOID lpAddress, DWORD dwSize, DWORD  flNewProtect, DWORD* lpflOldProtect)
{
    NTSTATUS Status = NtProtectVirtualMemory((HANDLE)-1, &lpAddress, &dwSize, flNewProtect, (PULONG)lpflOldProtect);
    if (!NT_SUCCESS(Status))
    {
        return FALSE;
    }
    return TRUE;
}
DWORD WINAPI IMP_VirtualQuery(PVOID lpAddress, PVOID lpBuffer, DWORD dwLength)
{
    NTSTATUS Status;
    ULONG ResultLength;
    Status = NtQueryVirtualMemory((HANDLE)-1, lpAddress, MemoryBasicInformation, lpBuffer, dwLength, &ResultLength);
    if (!NT_SUCCESS(Status))
    {
        return 0;
    }

    return ResultLength;
}

__declspec(naked) HANDLE IMP_GetProcessHeap()
{
    __asm
    {
        MOV EAX, DWORD PTR FS : [18h]
        MOV EAX, DWORD PTR DS : [EAX + 30h]
        MOV EAX, DWORD PTR DS : [EAX + 18h]
        RETN
    }
}

HMODULE WINAPI IMP_GetModuleHandleW(PWCHAR DllName)
{
    NT_TEB* pTeb = IMP_GetCurrentTEB();
    NT_PEB* pPeb = pTeb->Peb;
    //pPeb->BeingDebugged = 11;   
    PPEB_LDR_DATA pLdrData = pPeb->LoaderData;
    PLDR_MODULE  ListHead = (PLDR_MODULE)(&(pLdrData->InLoadOrderModuleList));
    PLDR_MODULE pLdrModule = (PLDR_MODULE)(((PLIST_ENTRY)ListHead)->Flink);

    if (DllName == 0)
        return (HMODULE)pPeb->ImageBaseAddress;

    while (pLdrModule != ListHead)
    {
        if (!IMP_wcsicmp(pLdrModule->BaseDllName.Buffer, DllName))
        {
            return (HMODULE)pLdrModule->BaseAddress;
        }

        pLdrModule = (PLDR_MODULE)pLdrModule->InLoadOrderModuleList.Flink;
    }
    return 0;
}

PVOID IMP_ForwardFunction(PCHAR ForwardChain);
PVOID WINAPI IMP_GetProcAddress(HMODULE ModuleBase, PCHAR FuncName)
{
    IMAGE_DOS_HEADER* mz_header = (IMAGE_DOS_HEADER*)ModuleBase;
    IMAGE_NT_HEADERS* pe_header = (IMAGE_NT_HEADERS*)((DWORD)mz_header + (DWORD)mz_header->e_lfanew);
    IMAGE_DATA_DIRECTORY* export_data = &pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*)((DWORD)mz_header + export_data->VirtualAddress);
    DWORD FuncRVA = 0;
    if ((DWORD)FuncName & 0xFFFF0000)
    {
        for (int i = 0; i < export_directory->NumberOfNames; i++)
        {
            PCHAR _Name = (PCHAR)((DWORD)mz_header + ((PULONG)((DWORD)mz_header + export_directory->AddressOfNames))[i]);
            if (IMP_strcmp(_Name, FuncName)) continue;
            DWORD index = ((WORD*)((DWORD)mz_header + export_directory->AddressOfNameOrdinals))[i];
            FuncRVA = ((DWORD*)((DWORD)mz_header + export_directory->AddressOfFunctions))[index];
        }

    }
    else if ((DWORD)FuncName >= export_directory->Base && (DWORD)FuncName <= export_directory->Base + export_directory->NumberOfFunctions - 1)
    {
        DWORD index = (WORD)(FuncName - export_directory->Base);
        FuncRVA = ((DWORD*)((DWORD)mz_header + export_directory->AddressOfFunctions))[index];
    }
    if (FuncRVA)
    {
        if (FuncRVA >= export_data->VirtualAddress && FuncRVA <= export_data->VirtualAddress + export_data->Size)
        {
            return IMP_ForwardFunction((PCHAR)((DWORD)mz_header + FuncRVA));
        }

        return (PVOID)((DWORD)mz_header + FuncRVA);
    }
    return 0;
}

PVOID IMP_ForwardFunction(PCHAR ForwardChain)
{
    PVOID retv = 0;

    __asm {
        mov eax, dword ptr[ForwardChain]
        mov esi, eax
        __looplen :
        cmp byte ptr[esi], 0
            je __over
            inc esi
            cmp byte ptr[esi], '.'
            je __getlen
            jmp __looplen
            __getlen :
        inc esi
            cmp byte ptr[esi], 0
            je __over
            sub esi, eax
            mov ecx, esi //len   
            lea eax, [esi + 4]
            mov dword ptr[esp - 4], 006C6C64h //dll\0 | 6C6C642Eh //.dll   
            sub esp, eax
            mov esi, dword ptr[ForwardChain] //to   
            mov edi, esp //from   
            push ecx //bakeup len   
            rep movsb
            lea eax, [esp + 4]
            push eax
            call dword ptr[IMP_LoadLibraryA]
            pop ecx //len   
            lea edx, [ecx + 4]
            add esp, edx
            mov edx, dword ptr[ForwardChain]
            add edx, ecx
            //inc edx   
            push edx
            push eax
            call IMP_GetProcAddress
            mov retv, eax
            jmp final
            __over:
        xor eax, eax
            mov retv, eax
    }
    final:
    return retv;
}

PVOID IMP_GetProcAddrByHash(HMODULE ModuleBase, DWORD Crc32Hash)
{
    IMAGE_DOS_HEADER* mz_header = (IMAGE_DOS_HEADER*)ModuleBase;
    IMAGE_NT_HEADERS* pe_header = (IMAGE_NT_HEADERS*)((DWORD)mz_header + (DWORD)mz_header->e_lfanew);
    IMAGE_DATA_DIRECTORY* export_data = &pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*)((DWORD)mz_header + export_data->VirtualAddress);
    DWORD FuncRVA = 0;
    for (int i = 0; i < export_directory->NumberOfNames; i++)
    {
        PCHAR _Name = (PCHAR)((DWORD)mz_header + ((PULONG)((DWORD)mz_header + export_directory->AddressOfNames))[i]);
        if (IMP_CRC32((PUCHAR)_Name, IMP_strlen(_Name)) != Crc32Hash) continue;

        DWORD index = ((WORD*)((DWORD)mz_header + export_directory->AddressOfNameOrdinals))[i];
        FuncRVA = ((DWORD*)((DWORD)mz_header + export_directory->AddressOfFunctions))[index];
    }
    if (FuncRVA)
    {
        if (FuncRVA >= export_data->VirtualAddress && FuncRVA <= export_data->VirtualAddress + export_data->Size)
        {
            return IMP_ForwardFunction((PCHAR)((DWORD)mz_header + FuncRVA));
        }
        return (PVOID)((DWORD)mz_header + FuncRVA);
    }
    return 0;
}
/////////////////////////////////////////////////////////////////////////////////////////   
void IMP_CrashProcess()
{
    __asm {
        mov eax, fs: [18h]
        mov ecx, [eax + 30h]
        xor ebx, ebx
        and [eax], ebx
        and [eax + 4], ebx
        and [eax + 8], ebx
        and [eax + 18h], ebx
        and [eax + 20h], ebx
        and [eax + 24h], ebx
        and [eax + 2Ch], ebx
        and [eax + 30h], ebx
        and [eax + 34h], ebx
        and [eax + 40h], ebx
        and [eax + 1A4h], ebx

        and [ecx + 8], ebx
        and [ecx + 0Ch], ebx
        and [ecx + 18h], ebx
        and [ecx + 20h], ebx
        and [ecx + 24h], ebx
        and [ecx + 2Ch], ebx
    }
}
//////////////////////////////////////////////////////////////////////////////////////////////   
__declspec(naked) void IMP_APIReter()
{
    __asm {
        sub esp, 4
        push eax
        mov eax, fs: [18h]
        add eax, 0C0h
        mov eax, [eax]
        mov fs : [0C0h] , 0
        not eax
        xor eax, [IMPer.Module]
        mov[esp + 4], eax
        cmp byte ptr[eax], 0CCh
        je cracker
        cmp byte ptr[eax], 0CDh
        je cracker
        pop eax
        retn

        cracker :
        call IMP_CrashProcess
            _loopc :
        __asm and esp, 0
        jmp _loopc
            __asm retn 1000h

    }
}
/////////////////////////////////////////////////////////////////////////////////////////////   
__declspec(naked) void IMP_APIEntry()
{
    __asm {
        push eax
        mov eax, [esp + 4] //RetAddr->key   
        xor dword ptr[esp + 8], 70000000h //decode with const key   
        xor dword ptr[esp + 8], eax //decode with RetAddr key   
        mov eax, dword ptr[esp + 8] //Get API addr   
        cmp byte ptr[eax], 0CCh
        je cracker
        cmp byte ptr[eax], 0CDh
        je cracker
        mov eax, fs: [0C0h]
        test eax, eax
        jne __noreter
        mov eax, [esp + 0Ch] //Get API RetAddr   
        xor eax, [IMPer.Module] //decode   
        not eax //decode   
        push eax
        mov eax, fs: [18h]
        add eax, 0C0h
        pop dword ptr[eax] //Bakup API RetAddr in TEB   
        lea eax, [IMP_APIReter]
        mov[esp + 0Ch], eax //Set API RetAddr   
        __noreter :
        pop eax
            add esp, 4
            retn

            cracker :
        call IMP_CrashProcess
            _loopc :
        __asm and esp, 0
        jmp _loopc
            __asm retn 1000h
    }
}
///////////////////////////////////////////////////////////////////////////////////////////   
PVOID IMP_MakeAPIEntry(PVOID ProcAddr)
{
    PVOID buf = IMP_RtlAllocateHeap(IMP_GetProcessHeap(), HEAP_ZERO_MEMORY, 10);
    if (buf)
    {
        *(PCHAR)buf = 0x68;
        *(DWORD*)((DWORD)buf + 1) = ((DWORD)ProcAddr ^ ((DWORD)buf + 10)) ^ 0x70000000;
        *(PCHAR)((DWORD)buf + 5) = 0xE8;
        *(DWORD*)((DWORD)buf + 6) = (DWORD)IMP_APIEntry - (((DWORD)buf + 5) + 5);
        return buf;
    }

    return 0;
}
BOOL IMP_MakeIAT(HMODULE hModule)
{
    IMAGE_DOS_HEADER* mz_header = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* pe_header = (IMAGE_NT_HEADERS*)((DWORD)mz_header + (DWORD)mz_header->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)mz_header + IMPer.ImportAddress);

    if (IMP_CRC32((PUCHAR)mz_header, pe_header->OptionalHeader.SizeOfHeaders) != IMPer.HeaderSum)
        return false;

    while (import_descriptor->OriginalFirstThunk && import_descriptor->FirstThunk)
    {
        HMODULE hDllModule = IMP_LoadLibraryA((PCHAR)((DWORD)mz_header + import_descriptor->Name));
        IMAGE_THUNK_DATA* FirstThunk = (IMAGE_THUNK_DATA*)((DWORD)mz_header + (DWORD)import_descriptor->FirstThunk);
        IMAGE_THUNK_DATA* OrgFirstThunk = (IMAGE_THUNK_DATA*)((DWORD)mz_header + (DWORD)import_descriptor->OriginalFirstThunk);
        while (OrgFirstThunk->u1.Ordinal)
        {
            DWORD oldflag;
            IMP_VirtualProtect((PVOID)&FirstThunk->u1.Ordinal, 4, PAGE_READWRITE, &oldflag);
            DWORD Ordinal = (WORD)(OrgFirstThunk->u1.Ordinal & 0x0000FFFF) ^ (WORD)((OrgFirstThunk->u1.Ordinal >> 8 & 0xFF00) | (OrgFirstThunk->u1.Ordinal >> 16 & 0x00FF));
            if (OrgFirstThunk->u1.Ordinal << 16 &&
                (OrgFirstThunk->u1.Ordinal >> 24) == 0x80 &&
                (OrgFirstThunk->u1.Ordinal & 0x00FF0000) &&
                (OrgFirstThunk->u1.Ordinal >> 16 & 0x00FF) == IMP_CRC8((PUCHAR)&Ordinal, 2)
                )
            {
                FirstThunk->u1.Ordinal = (DWORD)IMP_MakeAPIEntry(IMP_GetProcAddress(hDllModule, (PCHAR)Ordinal));
            }
            else if (OrgFirstThunk->u1.Ordinal == 0x6751B062)
            {
                FirstThunk->u1.Ordinal = (DWORD)IMP_GetProcAddress;
            }
            else
                FirstThunk->u1.Ordinal = (DWORD)IMP_MakeAPIEntry(IMP_GetProcAddrByHash(hDllModule, OrgFirstThunk->u1.Ordinal));

            IMP_VirtualProtect((PVOID)&FirstThunk->u1.Ordinal, 4, oldflag, &oldflag);
            FirstThunk++;
            OrgFirstThunk++;
        }

        import_descriptor++;
    }
    return true;
}
__declspec(naked) HMODULE IMP_GetSelfBase()
{
    __asm
    {
        sub esp, 28
        mov eax, esp
        push 28
        push eax
        call label0
        label0 :
        call IMP_VirtualQuery
            test eax, eax
            jz label1
            mov eax, [esp + 4]
            label1 :
            add esp, 28
            ret
    }
}

__declspec(naked) void IMP_MyDbgUiRemoteBreakin()
{
    IMP_CrashProcess();
    __asm retn 1000h
}

__declspec(naked) void IMP_MyRtlIsCurrentThreadAttachExempt()
{
    __asm {
        MOV EAX, DWORD PTR FS : [18h]
        CMP BYTE PTR DS : [EAX + 0FCAh] , 8
        je _c2
        TEST BYTE PTR DS : [EAX + 0FCAh] , 8
        JNZ _c1
        _c2 :
        XOR EAX, EAX
            RETN
            _c1 :
        MOV EAX, DWORD PTR FS : [18h]
            TEST BYTE PTR DS : [EAX + 0FCAh] , 20h
            JNZ _c2
            XOR EAX, EAX
            INC EAX
            RETN
    }
}
__declspec(naked) void IMP_ClientLoadLibrary()
{
    __asm retn 4
}

BOOL IMP_InitializeNtApiIndex()
{

    HMODULE NtDllBase = IMP_GetModuleHandleW((PWCHAR)"NTDLL.DLL");

    for (int i = 0; IMP_NtApiIndex[i]; i++)
    {
        PVOID AddrNtApi = IMP_GetProcAddrByHash(NtDllBase, IMP_NtApiIndex[i]);
        if (!AddrNtApi || *(PUCHAR)AddrNtApi != 0xB8)
            return false;
        IMP_NtApiIndex[i] = *(DWORD*)((DWORD)AddrNtApi + 1);
        
    }

    return true;
}

BOOL IMProtector()
{

    NT_PEB* Peb = IMP_GetCurrentTEB()->Peb;
    if (Peb->BeingDebugged || Peb->NtGlobalFlag == 0x70)
    {
        IMP_CrashProcess();
        /*
        while (1)
            __asm esp, 0
            __asm retn 1000h
        */
    }

    if (!IMPer.Initialized)
    {
        IMP_InitializeNtApiIndex();

        HMODULE Kernel32Base = IMP_GetModuleHandleW((PWCHAR)L"KERNEL32.DLL");
        IMP_LoadLibraryA = IMP_GetProcAddrByHash(Kernel32Base, (DWORD)IMP_LoadLibraryA);

        HMODULE NtDllBase = IMP_GetModuleHandleW((PWCHAR)L"NTDLL.DLL");

        IMP_RtlAllocateHeap = IMP_GetProcAddrByHash(NtDllBase, (DWORD)IMP_RtlAllocateHeap);

        IMP_DbgBreakPoint = IMP_GetProcAddrByHash(NtDllBase, (DWORD)IMP_DbgBreakPoint);
        IMP_DbgUiRemoteBreakin = IMP_GetProcAddrByHash(NtDllBase, (DWORD)IMP_DbgUiRemoteBreakin);
        IMP_RtlIsCurrentThreadAttachExempt = (PVOID)IMP_GetProcAddrByHash(NtDllBase, (DWORD)IMP_RtlIsCurrentThreadAttachExempt);

        KERNEL_USER_TIMES kutime = { 0 };
        NTSTATUS _s1 = NtQueryInformationProcess((HANDLE)-1, ProcessTimes, &kutime, sizeof(KERNEL_USER_TIMES), 0);
        
        if (!NT_SUCCESS(_s1) || (IMPer.EntryTime - kutime.CreateTime) > IMP_ENTRY_TIME_THRESHOLD)
        {
            IMP_CrashProcess();
            /*
            while (1)
                __asm esp, 0
                __asm retn 1000h
            */
        }

        DWORD oldflag;
        if (IMP_RtlIsCurrentThreadAttachExempt && IMP_VirtualProtect(IMP_RtlIsCurrentThreadAttachExempt, 5, PAGE_EXECUTE_READWRITE, &oldflag))
        {
            *(PCHAR)IMP_RtlIsCurrentThreadAttachExempt = 0xE9;
            *(DWORD*)((DWORD)IMP_RtlIsCurrentThreadAttachExempt + 1) = (DWORD)IMP_MyRtlIsCurrentThreadAttachExempt - ((DWORD)IMP_RtlIsCurrentThreadAttachExempt + 5);
            IMP_VirtualProtect(IMP_RtlIsCurrentThreadAttachExempt, 5, oldflag, &oldflag);
        }
        IMPer.Initialized = 1;
    }

    NtSetInformationThread((HANDLE)-2, ThreadHideFromDebugger, 0, 0);

    HANDLE DebugPort = 0;
    NtQueryInformationProcess((HANDLE)-1, ProcessDebugPort, &DebugPort, sizeof(HANDLE), 0);
    if (DebugPort)
    {
        IMP_CrashProcess();
        /*
        while (1)
            __asm esp, 0
            __asm retn 1000h
        */
    }

    DWORD oldflag;
    if (IMP_DbgUiRemoteBreakin && IMP_VirtualProtect(IMP_DbgUiRemoteBreakin, 5, PAGE_EXECUTE_READWRITE, &oldflag))
    {
        *(PCHAR)IMP_DbgUiRemoteBreakin = 0xE9;
        *(DWORD*)((DWORD)IMP_DbgUiRemoteBreakin + 1) = (DWORD)IMP_MyDbgUiRemoteBreakin - ((DWORD)IMP_DbgUiRemoteBreakin + 5);
        IMP_VirtualProtect(IMP_DbgUiRemoteBreakin, 5, oldflag, &oldflag);
    }
    if (IMP_DbgBreakPoint && IMP_VirtualProtect(IMP_DbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &oldflag))
    {
        *(PCHAR)IMP_DbgBreakPoint = 0xC3;
        IMP_VirtualProtect(IMP_DbgBreakPoint, 1, oldflag, &oldflag);
    }

    HMODULE User32Base = IMP_LoadLibraryA((PCHAR)"USER32.DLL");

    DWORD _iClientLoadLibrary = 0;
    if (IMP_USDATA->NtMajorVersion == 5 && IMP_USDATA->NtMinorVersion == 1)
        _iClientLoadLibrary = 66;
    else if (IMP_USDATA->NtMajorVersion == 6 && IMP_USDATA->NtMinorVersion == 1)
        _iClientLoadLibrary = 65;

    PVOID ClientLoadLibrary = IMP_GetCurrentTEB()->Peb->KernelCallbackTable[_iClientLoadLibrary];

    if (User32Base && _iClientLoadLibrary && ClientLoadLibrary)
    {
        if (IMP_VirtualProtect(ClientLoadLibrary, 4, PAGE_EXECUTE_READWRITE, &oldflag))
        {
            *(DWORD*)ClientLoadLibrary = 0xCC0004C2;
            IMP_VirtualProtect(ClientLoadLibrary, 4, oldflag, &oldflag);
        }
        if (IMP_VirtualProtect(&IMP_GetCurrentTEB()->Peb->KernelCallbackTable[_iClientLoadLibrary], 4, PAGE_EXECUTE_READWRITE, &oldflag))
        {
            IMP_GetCurrentTEB()->Peb->KernelCallbackTable[_iClientLoadLibrary] = (PVOID)IMP_ClientLoadLibrary;
            IMP_VirtualProtect(&IMP_GetCurrentTEB()->Peb->KernelCallbackTable[_iClientLoadLibrary], 4, oldflag, &oldflag);
        }
    }

    IMPer.Module = IMP_GetSelfBase();
    IMP_MakeIAT(IMPer.Module);

    return true;
}
//*   

#if IMP_TLS_ENABLE   
#pragma comment(linker, "/INCLUDE:__tls_used")   
BOOL IMP_CheckThreadStartAddress(DWORD ThreadStartup)
{
    if (ThreadStartup == (DWORD)IMP_LoadLibraryA)
        return false;

    NT_PEB* pPeb = IMP_GetCurrentTEB()->Peb;
    PPEB_LDR_DATA pLdrData = pPeb->LoaderData;
    PLDR_MODULE  ListHead = (PLDR_MODULE)(&(pLdrData->InLoadOrderModuleList));
    PLDR_MODULE pLdrModule = (PLDR_MODULE)(((PLIST_ENTRY)ListHead)->Flink);

    while (pLdrModule != ListHead)
    {
        //MessageBoxW(0,pLdrModule->BaseDllName.Buffer,"stchk",0);   
        if (ThreadStartup >= pLdrModule->BaseAddress && ThreadStartup <= (pLdrModule->BaseAddress + pLdrModule->SizeOfImage))
        {
            return true;
        }

        pLdrModule = (PLDR_MODULE)pLdrModule->InLoadOrderModuleList.Flink;
    }

    return false;

}
void NTAPI TMP_TlsCallBackFunction(PVOID Handle, DWORD Reason, PVOID Reserve)
{
    NT_PEB* Peb = IMP_GetCurrentTEB()->Peb;
    if (Peb->BeingDebugged || Peb->NtGlobalFlag == 0x70)
    {
        IMP_CrashProcess();
        /*
        while (1)
            __asm esp, 0
            __asm retn 1000h
        */
    }
    if (Reason == DLL_PROCESS_ATTACH)
    {
        IMAGE_DOS_HEADER* mz_header = (IMAGE_DOS_HEADER*)IMP_GetCurrentTEB()->Peb->ImageBaseAddress;
        IMAGE_NT_HEADERS* pe_header = (IMAGE_NT_HEADERS*)((DWORD)mz_header + (DWORD)mz_header->e_lfanew);
        PVOID EntryPoint = (PVOID)((DWORD)mz_header + pe_header->OptionalHeader.AddressOfEntryPoint);

        if (*(PUCHAR)EntryPoint == 0xCC || *(PUCHAR)EntryPoint == 0xCD)
        {
            IMP_CrashProcess();
            /*
            while (1)
                __asm esp, 0
                __asm retn 1000h
            */
        }
    }

    if (Reason == DLL_THREAD_ATTACH)
    {
        NtSetInformationThread((HANDLE)-2, ThreadHideFromDebugger, 0, 0);

        HANDLE DebugPort = 0;
        NtQueryInformationProcess((HANDLE)-1, ProcessDebugPort, &DebugPort, sizeof(HANDLE), 0);
        if (DebugPort)
        {
            IMP_CrashProcess();
            /*
            while (1)
                __asm esp, 0
                __asm retn 1000h
            */
        }

        DWORD ThreadStartup = 0;
        NtQueryInformationThread((HANDLE)-2, ThreadQuerySetWin32StartAddress, &ThreadStartup, sizeof(DWORD), 0);
        
        if (!ThreadStartup || *(PUCHAR)ThreadStartup == 0xCC || *(PUCHAR)ThreadStartup == 0xCD ||
            ThreadStartup == (DWORD)IMP_DbgUiRemoteBreakin || ThreadStartup == (DWORD)IMP_DbgBreakPoint)
        {   

            IMP_CrashProcess();
            /*
            while (1)
                __asm esp, 0
                __asm retn 1000h
            */
        }
        if (!IMPer.Initialized || !IMP_CheckThreadStartAddress(ThreadStartup))
        {
            NtTerminateThread((HANDLE)-2, 0);
            IMP_CrashProcess();
            /*
            while (1)
                __asm esp, 0
                __asm retn 1000h
            */
        }

    }  
}
extern "C" {
    int IMP_Tls_Index = 0, IMP_Tls_Start = 0, IMP_Tls_End = 0;
    PIMAGE_TLS_CALLBACK IMP_Tls_CallBackTable[] = { TMP_TlsCallBackFunction,NULL };
    IMAGE_TLS_DIRECTORY32 _tls_used = { (DWORD)&IMP_Tls_Start,(DWORD)&IMP_Tls_End,(DWORD)&IMP_Tls_Index,(DWORD)IMP_Tls_CallBackTable,0,0 };
}
#endif   

void __declspec(naked) IMP_Entry(void)
{
    __asm {
        pushad
        mov edx, 7FFE0000h
        lea ecx, [IMPer.EntryTime]
        mov eax, [edx + 14h]
        mov[ecx], eax
        mov eax, [edx + 18h]
        mov[ecx + 4], eax
        popad
        pushad
        pushfd
        call IMProtector
        popfd
        popad
        push IMPer.Entry;
        retn
    }
}
