typedef LONG NTSTATUS;
#define NT_SUCCESS(status)  ((NTSTATUS)(status)>=0) 

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _CLIENT_ID       // 2 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     VOID* UniqueProcess;
	/*0x004*/     VOID* UniqueThread;
}CLIENT_ID, * PCLIENT_ID;

typedef struct _KSYSTEM_TIME // 3 elements, 0xC bytes (sizeof) 
{
	/*0x000*/     ULONG32      LowPart;
	/*0x004*/     LONG32       High1Time;
	/*0x008*/     LONG32       High2Time;
}KSYSTEM_TIME, * PKSYSTEM_TIME;

typedef struct _LDR_MODULE {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	DWORD BaseAddress;
	DWORD EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA
{
	ULONG		Length;
	BOOLEAN		Initialized;
	BYTE        reserved[3];
	PVOID		SsHandle;
	LIST_ENTRY	InLoadOrderModuleList;
	LIST_ENTRY	InMemoryOrderModuleList;
	LIST_ENTRY	InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _NT_PEB  // 65 elements, 0x210 bytes (sizeof) 
{
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	/*0x003*/     UINT8        SpareBool;
	/*0x004*/     VOID* Mutant;
	/*0x008*/     VOID* ImageBaseAddress;
	/*0x00C*/     PEB_LDR_DATA* LoaderData;
	/*0x010*/     PVOID __b1;//RTL_USER_PROCESS_PARAMETERS* ProcessParameters; 
	/*0x014*/     VOID* SubSystemData;
	/*0x018*/     VOID* ProcessHeap;
	/*0x01C*/     PVOID __b2;//RTL_CRITICAL_SECTION* FastPebLock; 
	/*0x020*/     VOID* FastPebLockRoutine;
	/*0x024*/     VOID* FastPebUnlockRoutine;
	/*0x028*/     ULONG32      EnvironmentUpdateCount;
	/*0x02C*/     PVOID* KernelCallbackTable;
	/*0x030*/     ULONG32      SystemReserved[1];
	/*0x034*/     ULONG32      AtlThunkSListPtr32;
	/*0x038*/     PVOID __b3;//PEB_FREE_BLOCK* FreeList; 
	/*0x03C*/     ULONG32      TlsExpansionCounter;
	/*0x040*/     VOID* TlsBitmap;
	/*0x044*/     ULONG32      TlsBitmapBits[2];
	/*0x04C*/     VOID* ReadOnlySharedMemoryBase;
	/*0x050*/     VOID* ReadOnlySharedMemoryHeap;
	/*0x054*/     VOID** ReadOnlyStaticServerData;
	/*0x058*/     VOID* AnsiCodePageData;
	/*0x05C*/     VOID* OemCodePageData;
	/*0x060*/     VOID* UnicodeCaseTableData;
	/*0x064*/     ULONG32      NumberOfProcessors;
	/*0x068*/     ULONG32      NtGlobalFlag;
	/*0x06C*/     UINT8        _PADDING0_[0x4];
	/*0x070*/     LARGE_INTEGER CriticalSectionTimeout; // 4 elements, 0x8 bytes (sizeof) 
	/*0x078*/     ULONG32      HeapSegmentReserve;
	/*0x07C*/     ULONG32      HeapSegmentCommit;
	/*0x080*/     ULONG32      HeapDeCommitTotalFreeThreshold;
	/*0x084*/     ULONG32      HeapDeCommitFreeBlockThreshold;
	/*0x088*/     ULONG32      NumberOfHeaps;
	/*0x08C*/     ULONG32      MaximumNumberOfHeaps;
	/*0x090*/     VOID** ProcessHeaps;
	/*0x094*/     VOID* GdiSharedHandleTable;
	/*0x098*/     VOID* ProcessStarterHelper;
	/*0x09C*/     ULONG32      GdiDCAttributeList;
	/*0x0A0*/     VOID* LoaderLock;
	/*0x0A4*/     ULONG32      OSMajorVersion;
	/*0x0A8*/     ULONG32      OSMinorVersion;
	/*0x0AC*/     UINT16       OSBuildNumber;
	/*0x0AE*/     UINT16       OSCSDVersion;
	/*0x0B0*/     ULONG32      OSPlatformId;
	/*0x0B4*/     ULONG32      ImageSubsystem;
	/*0x0B8*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x0BC*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x0C0*/     ULONG32      ImageProcessAffinityMask;
	/*0x0C4*/     ULONG32      GdiHandleBuffer[34];
	/*0x14C*/     PVOID PostProcessInitRoutine;
	/*0x150*/     VOID* TlsExpansionBitmap;
	/*0x154*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x1D4*/     ULONG32      SessionId;
	/*0x1D8*/     ULARGE_INTEGER AppCompatFlags;  // 4 elements, 0x8 bytes (sizeof) 
	/*0x1E0*/     ULARGE_INTEGER AppCompatFlagsUser; // 4 elements, 0x8 bytes (sizeof) 
	/*0x1E8*/     VOID* pShimData;
	/*0x1EC*/     VOID* AppCompatInfo;
	/*0x1F0*/     UNICODE_STRING CSDVersion; // 3 elements, 0x8 bytes (sizeof) 
	/*0x1F8*/     VOID* ActivationContextData;
	/*0x1FC*/     VOID* ProcessAssemblyStorageMap;
	/*0x200*/     VOID* SystemDefaultActivationContextData;
	/*0x204*/     VOID* SystemAssemblyStorageMap;
	/*0x208*/     ULONG32      MinimumStackCommit;
	/*0x20C*/     UINT8        _PADDING1_[0x4];
}NT_PEB, * PNT_PEB;

typedef struct _NT_TEB  // 64 elements, 0xFB4 bytes (sizeof) 
{
	/*0x000*/     NT_TIB       NtTib; // 8 elements, 0x1C bytes (sizeof) 
	/*0x01C*/     VOID* EnvironmentPointer;
	/*0x020*/     CLIENT_ID    ClientId; // 2 elements, 0x8 bytes (sizeof) 
	/*0x028*/     VOID* ActiveRpcHandle;
	/*0x02C*/     VOID* ThreadLocalStoragePointer;
	/*0x030*/     NT_PEB* Peb;
	/*0x034*/     ULONG32      LastErrorValue;
	/*0x038*/     ULONG32      CountOfOwnedCriticalSections;
	/*0x03C*/     VOID* CsrClientThread;
	/*0x040*/     VOID* Win32ThreadInfo;
	/*0x044*/     ULONG32      User32Reserved[26];
	/*0x0AC*/     ULONG32      UserReserved[5];
	/*0x0C0*/     VOID* WOW32Reserved;
	/*0x0C4*/     ULONG32      CurrentLocale;
	/*0x0C8*/     ULONG32      FpSoftwareStatusRegister;
	/*0x0CC*/     VOID* SystemReserved1[54];
	/*0x1A4*/     LONG32       ExceptionCode;
	/*0x1A8*/     BYTE __b1[0x14];//ACTIVATION_CONTEXT_STACK ActivationContextStack; // 4 elements, 0x14 bytes (sizeof) 
	/*0x1BC*/     UINT8        SpareBytes1[24];
	/*0x1D4*/     BYTE __b2[0x4E0];//GDI_TEB_BATCH GdiTebBatch;                       // 3 elements, 0x4E0 bytes (sizeof) 
	/*0x6B4*/     CLIENT_ID RealClientId;                          // 2 elements, 0x8 bytes (sizeof) 
	/*0x6BC*/     VOID* GdiCachedProcessHandle;
	/*0x6C0*/     ULONG32      GdiClientPID;
	/*0x6C4*/     ULONG32      GdiClientTID;
	/*0x6C8*/     VOID* GdiThreadLocalInfo;
	/*0x6CC*/     ULONG32      Win32ClientInfo[62];
	/*0x7C4*/     VOID* glDispatchTable[233];
	/*0xB68*/     ULONG32      glReserved1[29];
	/*0xBDC*/     VOID* glReserved2;
	/*0xBE0*/     VOID* glSectionInfo;
	/*0xBE4*/     VOID* glSection;
	/*0xBE8*/     VOID* glTable;
	/*0xBEC*/     VOID* glCurrentRC;
	/*0xBF0*/     VOID* glContext;
	/*0xBF4*/     ULONG32      LastStatusValue;
	/*0xBF8*/     UNICODE_STRING StaticUnicodeString; // 3 elements, 0x8 bytes (sizeof) 
	/*0xC00*/     UINT16       StaticUnicodeBuffer[261];
	/*0xE0A*/     UINT8        _PADDING0_[0x2];
	/*0xE0C*/     VOID* DeallocationStack;
	/*0xE10*/     VOID* TlsSlots[64];
	/*0xF10*/     LIST_ENTRY TlsLinks; // 2 elements, 0x8 bytes (sizeof) 
	/*0xF18*/     VOID* Vdm;
	/*0xF1C*/     VOID* ReservedForNtRpc;
	/*0xF20*/     VOID* DbgSsReserved[2];
	/*0xF28*/     ULONG32      HardErrorsAreDisabled;
	/*0xF2C*/     VOID* Instrumentation[16];
	/*0xF6C*/     VOID* WinSockData;
	/*0xF70*/     ULONG32      GdiBatchCount;
	/*0xF74*/     UINT8        InDbgPrint;
	/*0xF75*/     UINT8        FreeStackOnTermination;
	/*0xF76*/     UINT8        HasFiberData;
	/*0xF77*/     UINT8        IdealProcessor;
	/*0xF78*/     ULONG32      Spare3;
	/*0xF7C*/     VOID* ReservedForPerf;
	/*0xF80*/     VOID* ReservedForOle;
	/*0xF84*/     ULONG32      WaitingOnLoaderLock;
	/*0xF88*/     BYTE __b3[0xC];//Wx86ThreadState Wx86Thread; // 4 elements, 0xC bytes (sizeof) 
	/*0xF94*/     VOID** TlsExpansionSlots;
	/*0xF98*/     ULONG32      ImpersonationLocale;
	/*0xF9C*/     ULONG32      IsImpersonating;
	/*0xFA0*/     VOID* NlsCache;
	/*0xFA4*/     VOID* pShimData;
	/*0xFA8*/     ULONG32      HeapVirtualAffinity;
	/*0xFAC*/     VOID* CurrentTransactionHandle;
	/*0xFB0*/     PVOID __b4;//TEB_ACTIVE_FRAME* ActiveFrame; 
}NT_TEB, * PNT_TEB;

typedef struct _KUSER_SHARED_DATA                                // 39 elements, 0x338 bytes (sizeof) 
{
	/*0x000*/     ULONG32      TickCountLow;
	/*0x004*/     ULONG32      TickCountMultiplier;
	/*0x008*/     KSYSTEM_TIME InterruptTime;                          // 3 elements, 0xC bytes (sizeof) 
	/*0x014*/     KSYSTEM_TIME SystemTime;                             // 3 elements, 0xC bytes (sizeof) 
	/*0x020*/     KSYSTEM_TIME TimeZoneBias;                           // 3 elements, 0xC bytes (sizeof) 
	/*0x02C*/     UINT16       ImageNumberLow;
	/*0x02E*/     UINT16       ImageNumberHigh;
	/*0x030*/     UINT16       NtSystemRoot[260];
	/*0x238*/     ULONG32      MaxStackTraceDepth;
	/*0x23C*/     ULONG32      CryptoExponent;
	/*0x240*/     ULONG32      TimeZoneId;
	/*0x244*/     ULONG32      Reserved2[8];
	/*0x264*/     DWORD __b1;//NT_PRODUCT_TYPE NtProductType; 
	/*0x268*/     UINT8        ProductTypeIsValid;
	/*0x269*/     UINT8        _PADDING0_[0x3];
	/*0x26C*/     ULONG32      NtMajorVersion;
	/*0x270*/     ULONG32      NtMinorVersion;
	/*0x274*/     UINT8        ProcessorFeatures[64];
	/*0x2B4*/     ULONG32      Reserved1;
	/*0x2B8*/     ULONG32      Reserved3;
	/*0x2BC*/     ULONG32      TimeSlip;
	/*0x2C0*/     DWORD __b2;//ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture; 
	/*0x2C4*/     UINT8        _PADDING1_[0x4];
	/*0x2C8*/     LARGE_INTEGER SystemExpirationDate;                   // 4 elements, 0x8 bytes (sizeof) 
	/*0x2D0*/     ULONG32      SuiteMask;
	/*0x2D4*/     UINT8        KdDebuggerEnabled;
	/*0x2D5*/     UINT8        NXSupportPolicy;
	/*0x2D6*/     UINT8        _PADDING2_[0x2];
	/*0x2D8*/     ULONG32      ActiveConsoleId;
	/*0x2DC*/     ULONG32      DismountCount;
	/*0x2E0*/     ULONG32      ComPlusPackage;
	/*0x2E4*/     ULONG32      LastSystemRITEventTickCount;
	/*0x2E8*/     ULONG32      NumberOfPhysicalPages;
	/*0x2EC*/     UINT8        SafeBootMode;
	/*0x2ED*/     UINT8        _PADDING3_[0x3];
	/*0x2F0*/     ULONG32      TraceLogging;
	/*0x2F4*/     UINT8        _PADDING4_[0x4];
	/*0x2F8*/     UINT64       TestRetInstruction;
	/*0x300*/     ULONG32      SystemCall;
	/*0x304*/     ULONG32      SystemCallReturn;
}KUSER_SHARED_DATA, * PKUSER_SHARED_DATA;
///////////////////////////////////////////////////////////////////////////////////// 
typedef enum _PROCESS_INFORMATION_CLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	MaxProcessInfoClass
} PROCESS_INFORMATION_CLASS, * PPROCESS_INFORMATION_CLASS;

typedef struct _KERNEL_USER_TIMES {
	LONGLONG  CreateTime;
	LONGLONG  ExitTime;
	LONGLONG  KernelTime;
	LONGLONG  UserTime;
}KERNEL_USER_TIMES, * PKERNEL_USER_TIMES;


typedef enum _THREAD_INFORMATION_CLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger
} THREAD_INFORMATION_CLASS, * PTHREAD_INFORMATION_CLASS;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName,
	MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

///////////////////////////////////////////////////////////////////////// 
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

BOOL IMProtector();
void IMP_Entry(void);

