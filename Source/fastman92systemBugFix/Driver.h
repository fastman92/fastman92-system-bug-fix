#pragma once
#include <windef.h>

#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning(disable : 4214)	// nonstandard extension used: bit field types other than int
#pragma warning(disable : 4201) // nonstandard extension used: nameless struct/union
#endif

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY     LoadOrder;
	LIST_ENTRY     MemoryOrder;
	LIST_ENTRY     InitializationOrder;
	PVOID          ModuleBaseAddress;
	PVOID          EntryPoint;
	ULONG          ModuleSize;
	UNICODE_STRING FullModuleName;
	UNICODE_STRING ModuleName;
	ULONG          Flags;
	USHORT         LoadCount;
	USHORT         TlsIndex;
	union {
		LIST_ENTRY Hash;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	ULONG   TimeStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// Redefinition of the IMAGE_LOAD_CONFIG_CODE_INTEGRITY structure. This
// corresponds to the structure as encountered in the version 10.0+ of the
// Windows SDK.
typedef struct {
	WORD Flags;
	WORD Catalog;
	DWORD CatalogOffset;
	DWORD Reserved;
} IMAGE_LOAD_CONFIG_CODE_INTEGRITY;

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY32 {
	DWORD                            Size;
	DWORD                            TimeDateStamp;
	WORD                             MajorVersion;
	WORD                             MinorVersion;
	DWORD                            GlobalFlagsClear;
	DWORD                            GlobalFlagsSet;
	DWORD                            CriticalSectionDefaultTimeout;
	DWORD                            DeCommitFreeBlockThreshold;
	DWORD                            DeCommitTotalFreeThreshold;
	DWORD                            LockPrefixTable;
	DWORD                            MaximumAllocationSize;
	DWORD                            VirtualMemoryThreshold;
	DWORD                            ProcessHeapFlags;
	DWORD                            ProcessAffinityMask;
	WORD                             CSDVersion;
	WORD                             DependentLoadFlags;
	DWORD                            EditList;
	DWORD                            SecurityCookie;
	DWORD                            SEHandlerTable;
	DWORD                            SEHandlerCount;
	DWORD                            GuardCFCheckFunctionPointer;
	DWORD                            GuardCFDispatchFunctionPointer;
	DWORD                            GuardCFFunctionTable;
	DWORD                            GuardCFFunctionCount;
	DWORD                            GuardFlags;
	IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
	DWORD                            GuardAddressTakenIatEntryTable;
	DWORD                            GuardAddressTakenIatEntryCount;
	DWORD                            GuardLongJumpTargetTable;
	DWORD                            GuardLongJumpTargetCount;
	DWORD                            DynamicValueRelocTable;
	DWORD                            CHPEMetadataPointer;
	DWORD                            GuardRFFailureRoutine;
	DWORD                            GuardRFFailureRoutineFunctionPointer;
	DWORD                            DynamicValueRelocTableOffset;
	WORD                             DynamicValueRelocTableSection;
	WORD                             Reserved2;
	DWORD                            GuardRFVerifyStackPointerFunctionPointer;
	DWORD                            HotPatchTableOffset;
	DWORD                            Reserved3;
	DWORD                            EnclaveConfigurationPointer;
	DWORD                            VolatileMetadataPointer;
	DWORD                            GuardEHContinuationTable;
	DWORD                            GuardEHContinuationCount;
	DWORD                            GuardXFGCheckFunctionPointer;
	DWORD                            GuardXFGDispatchFunctionPointer;
	DWORD                            GuardXFGTableDispatchFunctionPointer;
	DWORD                            CastGuardOsDeterminedFailureMode;
	DWORD                            GuardMemcpyFunctionPointer;
} windows_IMAGE_LOAD_CONFIG_DIRECTORY32, *windows_PIMAGE_LOAD_CONFIG_DIRECTORY32;

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY64 {
	DWORD                            Size;
	DWORD                            TimeDateStamp;
	WORD                             MajorVersion;
	WORD                             MinorVersion;
	DWORD                            GlobalFlagsClear;
	DWORD                            GlobalFlagsSet;
	DWORD                            CriticalSectionDefaultTimeout;
	ULONGLONG                        DeCommitFreeBlockThreshold;
	ULONGLONG                        DeCommitTotalFreeThreshold;
	ULONGLONG                        LockPrefixTable;
	ULONGLONG                        MaximumAllocationSize;
	ULONGLONG                        VirtualMemoryThreshold;
	ULONGLONG                        ProcessAffinityMask;
	DWORD                            ProcessHeapFlags;
	WORD                             CSDVersion;
	WORD                             DependentLoadFlags;
	ULONGLONG                        EditList;
	ULONGLONG                        SecurityCookie;
	ULONGLONG                        SEHandlerTable;
	ULONGLONG                        SEHandlerCount;
	ULONGLONG                        GuardCFCheckFunctionPointer;
	ULONGLONG                        GuardCFDispatchFunctionPointer;
	ULONGLONG                        GuardCFFunctionTable;
	ULONGLONG                        GuardCFFunctionCount;
	DWORD                            GuardFlags;
	IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
	ULONGLONG                        GuardAddressTakenIatEntryTable;
	ULONGLONG                        GuardAddressTakenIatEntryCount;
	ULONGLONG                        GuardLongJumpTargetTable;
	ULONGLONG                        GuardLongJumpTargetCount;
	ULONGLONG                        DynamicValueRelocTable;
	ULONGLONG                        CHPEMetadataPointer;
	ULONGLONG                        GuardRFFailureRoutine;
	ULONGLONG                        GuardRFFailureRoutineFunctionPointer;
	DWORD                            DynamicValueRelocTableOffset;
	WORD                             DynamicValueRelocTableSection;
	WORD                             Reserved2;
	ULONGLONG                        GuardRFVerifyStackPointerFunctionPointer;
	DWORD                            HotPatchTableOffset;
	DWORD                            Reserved3;
	ULONGLONG                        EnclaveConfigurationPointer;
	ULONGLONG                        VolatileMetadataPointer;
	ULONGLONG                        GuardEHContinuationTable;
	ULONGLONG                        GuardEHContinuationCount;
	ULONGLONG                        GuardXFGCheckFunctionPointer;
	ULONGLONG                        GuardXFGDispatchFunctionPointer;
	ULONGLONG                        GuardXFGTableDispatchFunctionPointer;
	ULONGLONG                        CastGuardOsDeterminedFailureMode;
	ULONGLONG                        GuardMemcpyFunctionPointer;
} windows_IMAGE_LOAD_CONFIG_DIRECTORY64, *windows_PIMAGE_LOAD_CONFIG_DIRECTORY64;

#ifdef _WIN64
typedef windows_IMAGE_LOAD_CONFIG_DIRECTORY64     windows_IMAGE_LOAD_CONFIG_DIRECTORY;
typedef windows_PIMAGE_LOAD_CONFIG_DIRECTORY64    windows_PIMAGE_LOAD_CONFIG_DIRECTORY;
#else
typedef windows_IMAGE_LOAD_CONFIG_DIRECTORY32     windows_IMAGE_LOAD_CONFIG_DIRECTORY;
typedef windows_PIMAGE_LOAD_CONFIG_DIRECTORY32    windows_PIMAGE_LOAD_CONFIG_DIRECTORY;
#endif

#pragma pack(push, 1)
typedef struct _IMAGE_DYNAMIC_RELOCATION_TABLE {
	DWORD Version;
	DWORD Size;
	//  IMAGE_DYNAMIC_RELOCATION DynamicRelocations[0];
} windows_IMAGE_DYNAMIC_RELOCATION_TABLE, *windows_PIMAGE_DYNAMIC_RELOCATION_TABLE;

typedef struct _IMAGE_DYNAMIC_RELOCATION32 {
	DWORD      Symbol;
	DWORD      BaseRelocSize;
	//  IMAGE_BASE_RELOCATION BaseRelocations[0];
} IMAGE_DYNAMIC_RELOCATION32, *PIMAGE_DYNAMIC_RELOCATION32;

typedef struct _IMAGE_DYNAMIC_RELOCATION64 {
	ULONGLONG  Symbol;
	DWORD      BaseRelocSize;
	//  IMAGE_BASE_RELOCATION BaseRelocations[0];
} IMAGE_DYNAMIC_RELOCATION64, *PIMAGE_DYNAMIC_RELOCATION64;

typedef struct _IMAGE_DYNAMIC_RELOCATION32_V2 {
	DWORD      HeaderSize;
	DWORD      FixupInfoSize;
	DWORD      Symbol;
	DWORD      SymbolGroup;
	DWORD      Flags;
	// ...     variable length header fields
	// BYTE    FixupInfo[FixupInfoSize]
} IMAGE_DYNAMIC_RELOCATION32_V2, *PIMAGE_DYNAMIC_RELOCATION32_V2;

typedef struct _IMAGE_DYNAMIC_RELOCATION64_V2 {
	DWORD      HeaderSize;
	DWORD      FixupInfoSize;
	ULONGLONG  Symbol;
	DWORD      SymbolGroup;
	DWORD      Flags;
	// ...     variable length header fields
	// BYTE    FixupInfo[FixupInfoSize]
} IMAGE_DYNAMIC_RELOCATION64_V2, *PIMAGE_DYNAMIC_RELOCATION64_V2;
#pragma pack(pop)

#ifdef _WIN64
typedef IMAGE_DYNAMIC_RELOCATION64          IMAGE_DYNAMIC_RELOCATION;
typedef PIMAGE_DYNAMIC_RELOCATION64         PIMAGE_DYNAMIC_RELOCATION;
typedef IMAGE_DYNAMIC_RELOCATION64_V2       IMAGE_DYNAMIC_RELOCATION_V2;
typedef PIMAGE_DYNAMIC_RELOCATION64_V2      PIMAGE_DYNAMIC_RELOCATION_V2;
#else
typedef IMAGE_DYNAMIC_RELOCATION32          IMAGE_DYNAMIC_RELOCATION;
typedef PIMAGE_DYNAMIC_RELOCATION32         PIMAGE_DYNAMIC_RELOCATION;
typedef IMAGE_DYNAMIC_RELOCATION32_V2       IMAGE_DYNAMIC_RELOCATION_V2;
typedef PIMAGE_DYNAMIC_RELOCATION32_V2      PIMAGE_DYNAMIC_RELOCATION_V2;
#endif

//
// Defined symbolic dynamic relocation entries.
//

#define IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE   0x00000001
#define IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE   0x00000002
#define IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER  0x00000003
#define IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER   0x00000004
#define IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH       0x00000005

typedef struct _IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION {
	DWORD       PageRelativeOffset : 12;
	DWORD       IndirectCall : 1;
	DWORD       IATIndex : 19;
} IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION;
typedef IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION  * PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION;

#if defined(_MSC_VER)
#pragma warning( pop )
#endif