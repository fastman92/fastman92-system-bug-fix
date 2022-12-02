#include <ntddk.h>
#include <wdf.h>

#include "Driver.h"
#include "ntimage.h"

#include <stdarg.h>
#include <windef.h>
#include <wchar.h>

DRIVER_INITIALIZE DriverEntry;


PLIST_ENTRY g_LoadOrderListHead = NULL;

PLDR_DATA_TABLE_ENTRY
KernelGetModuleLdrEntry(
	PDRIVER_OBJECT DriverObject,
	PCHAR  pModuleName
)
{
	PLDR_DATA_TABLE_ENTRY pModuleLDRentry = NULL;
	PLIST_ENTRY Next;
	PLIST_ENTRY LoadOrderListHead;
	UNICODE_STRING uStr;
	PLDR_DATA_TABLE_ENTRY LdrDataTableEntry;
	PLDR_DATA_TABLE_ENTRY LdrDataTableEntry0;
	ULONG len;
	BOOLEAN FreeUstr = FALSE;

	uStr.Buffer = NULL;

	__try
	{
		if (!g_LoadOrderListHead) {
			LdrDataTableEntry0 = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

			uStr.Length = sizeof(L"NTOSKRNL.EXE") - sizeof(WCHAR);
			uStr.MaximumLength = sizeof(L"NTOSKRNL.EXE");
			uStr.Buffer = L"NTOSKRNL.EXE";

			Next = LdrDataTableEntry0->LoadOrder.Blink;

			while (TRUE) {
				LdrDataTableEntry = CONTAINING_RECORD(Next,
					LDR_DATA_TABLE_ENTRY,
					LoadOrder
				);
				
				Next = Next->Blink;
				if (!LdrDataTableEntry->ModuleName.Buffer) {
					return NULL;
				}

				if (RtlCompareUnicodeString(&LdrDataTableEntry->ModuleName, &uStr, TRUE) == 0)
				{
					LoadOrderListHead = Next;
					break;
				}
				if (LdrDataTableEntry == LdrDataTableEntry0)
					return NULL;
			}

			g_LoadOrderListHead = LoadOrderListHead;
		}
		else {
			LoadOrderListHead = g_LoadOrderListHead;
		}
		len = (ULONG)strlen(pModuleName);
		if (!len)
			return NULL;
		len = (len + 1) * sizeof(WCHAR);

		uStr.MaximumLength = (USHORT)len;
		uStr.Length = (USHORT)len - sizeof(WCHAR);
		uStr.Buffer = (PWCHAR)ExAllocatePool(NonPagedPool, len);
		FreeUstr = TRUE;
		swprintf(uStr.Buffer, L"%S", pModuleName);

		Next = LoadOrderListHead->Flink;
		while (Next != LoadOrderListHead) {
			LdrDataTableEntry = CONTAINING_RECORD(Next,
				LDR_DATA_TABLE_ENTRY,
				LoadOrder
			);
			if (RtlCompareUnicodeString(&LdrDataTableEntry->ModuleName, &uStr, TRUE) == 0)
			{
				pModuleLDRentry = LdrDataTableEntry;
				break;
			}
			Next = Next->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		pModuleLDRentry = NULL;
	}
	if (FreeUstr && uStr.Buffer) {
		ExFreePool(uStr.Buffer);
	}

	return pModuleLDRentry;
} // end KernelGetModuleBase3()

// windows IATHook for kernelmode and usermode 
// by TinySec( root@tinysec.net )
void*  _IATHook_InterlockedExchangePointer(__in void* pAddress, __in void* pValue)
{
	void*	pWriteableAddr = NULL;
	PMDL	pNewMDL = NULL;
	void*	pOld = NULL;

	do
	{
		if ((NULL == pAddress))
		{
			break;
		}

		if (!NT_SUCCESS(MmIsAddressValid(pAddress)))
		{
			break;
		}

		pNewMDL = IoAllocateMdl(pAddress, sizeof(void*), FALSE, FALSE, NULL);
		if (pNewMDL == NULL)
		{
			break;
		}

		__try
		{
			MmProbeAndLockPages(pNewMDL, KernelMode, IoReadAccess);

			pNewMDL->MdlFlags |= MDL_MAPPING_CAN_FAIL;

			pWriteableAddr = MmMapLockedPagesSpecifyCache(
				pNewMDL,
				KernelMode,
				MmNonCached,
				NULL,
				FALSE,
				HighPagePriority
			);

			MmProtectMdlSystemAddress(pNewMDL, PAGE_READWRITE);

			//pWriteableAddr = MmMapLockedPages(pNewMDL, KernelMode);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}

		if (pWriteableAddr == NULL)
		{
			MmUnlockPages(pNewMDL);
			IoFreeMdl(pNewMDL);

			break;
		}

		pOld = InterlockedExchangePointer(pWriteableAddr, pValue);

		MmUnmapLockedPages(pWriteableAddr, pNewMDL);
		MmUnlockPages(pNewMDL);
		IoFreeMdl(pNewMDL);

	} while (FALSE);

	return pOld;
}

/*
// Writes data to protected memory
void* WriteDataToMemory(__in void* pAddress, __in const void* bData, __in int iSize)
{
	void*	pWriteableAddr = NULL;
	PMDL	pNewMDL = NULL;
	void*	pOld = NULL;

	do
	{
		if ((NULL == pAddress))
		{
			break;
		}

		if (!NT_SUCCESS(MmIsAddressValid(pAddress)))
		{
			break;
		}

		pNewMDL = IoAllocateMdl(pAddress, sizeof(void*), FALSE, FALSE, NULL);
		if (pNewMDL == NULL)
		{
			break;
		}

		__try
		{
			MmProbeAndLockPages(pNewMDL, KernelMode, IoReadAccess);

			pNewMDL->MdlFlags |= MDL_MAPPING_CAN_FAIL;

			pWriteableAddr = MmMapLockedPagesSpecifyCache(
				pNewMDL,
				KernelMode,
				MmNonCached,
				NULL,
				FALSE,
				HighPagePriority
			);

			MmProtectMdlSystemAddress(pNewMDL, PAGE_READWRITE);

			//pWriteableAddr = MmMapLockedPages(pNewMDL, KernelMode);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}

		if (pWriteableAddr == NULL)
		{
			MmUnlockPages(pNewMDL);
			IoFreeMdl(pNewMDL);

			break;
		}

		memcpy(pAddress, bData, iSize);
		// pOld = InterlockedExchangePointer(pWriteableAddr, pValue);

		MmUnmapLockedPages(pWriteableAddr, pNewMDL);
		MmUnlockPages(pNewMDL);
		IoFreeMdl(pNewMDL);

	} while (FALSE);

	return pOld;
}
*/

//Use UserMode as KPROCESSOR_MODE when attaching to a usermode process
NTSTATUS WriteMemory(PVOID Destination, PVOID Buffer, ULONG BufferSize, ULONG fProtect) // Write memory
{
	PMDL mdl = IoAllocateMdl(Destination, BufferSize, FALSE, FALSE, NULL); // Allocate Memory Descriptor
	// Many MDL functions must be enclosed in a try/except statement
	__try
	{
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		Destination = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);

		MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE); // Set the page rights to R/W/X
		RtlCopyMemory(Destination, Buffer, BufferSize); // Write Memory
		MmProtectMdlSystemAddress(mdl, fProtect); // Set back to old page rights

		MmUnmapLockedPages(Destination, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl); // free MDL
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 1;
	}

	return 0;
}

//Use UserMode as KPROCESSOR_MODE when attaching to a usermode process
NTSTATUS ProcessRelocEntries(
	PVOID pageAddress,
	PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION pEntriesPerPage,
	unsigned int CountOfEntriesPerPage,
	unsigned int ToBeChangedIATindex,
	PVOID* pFunctionAddress)
{
	UNREFERENCED_PARAMETER(pFunctionAddress);
	PVOID origPageAddress = pageAddress;

	PMDL mdl = IoAllocateMdl(pageAddress, 4096 /* page size */, FALSE, FALSE, NULL); // Allocate Memory Descriptor
// Many MDL functions must be enclosed in a try/except statement
	__try
	{
		
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		pageAddress = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);

		MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE); // Set the page rights to R/W/X

		for (unsigned int i = 0; i < CountOfEntriesPerPage; i++)
		{
			PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION pReloc = pEntriesPerPage + i;

			if (pReloc->IATIndex != ToBeChangedIATindex)
				continue;

			PCHAR Address = (PCHAR)origPageAddress + pReloc->PageRelativeOffset;

			unsigned char newData[12];
			newData[0] = 0x48;	// call qword ptr
			newData[1] = 0xFF;
			newData[2] = 0x15;

			LONG rel_to_ip = (LONG)((PCHAR)pFunctionAddress - (Address + 7));
			RtlCopyMemory(newData + 3, &rel_to_ip, 4);

			newData[7] = 0x0F;
			newData[8] = 0x1f;
			newData[9] = 0x44;
			newData[10] = 0x00;
			newData[11] = 0x00;

			RtlCopyMemory((PCHAR)pageAddress + pReloc->PageRelativeOffset, newData, sizeof(newData)); // Write Memory
		}
		
		MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READ); // Set back to old page rights

		MmUnmapLockedPages(pageAddress, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl); // free MDL
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 1;
	}

	return 0;
}

ULONG
__cdecl
DbgPrintExReplacementForUSBXHCI(
	_In_ ULONG ComponentId,
	_In_ ULONG Level,
	_In_z_ _Printf_format_string_ PCSTR Format,
	...
)
{
	va_list a_list;
	va_start(a_list, Format);

	if (ComponentId == 147 /* USBXHCI */
		&& !strcmp(Format, "XHCIDUMP: Crashdump_Command_TestCommandRingOperation: end 0x%X\n")
		)
	{
		// DbgPrint("Stalling\n");

		KeStallExecutionProcessor(1000000);
	}

	ULONG result = vDbgPrintEx(ComponentId, Level, Format, a_list);
	va_end(a_list);

	return result;
}

#define IMAGE_GUARD_RETPOLINE_PRESENT                  0x00100000 // Module was built with retpoline support



PVOID* pDbgPrintFunctionAddress = NULL; // in USBXHCI.sys
void* originalDbgPrint = NULL;

VOID
DriverUnload(
	_In_ struct _DRIVER_OBJECT *DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	if(pDbgPrintFunctionAddress)
		_IATHook_InterlockedExchangePointer(pDbgPrintFunctionAddress, originalDbgPrint);
}

typedef struct
{
	HANDLE fileHandle;
	IO_STATUS_BLOCK    ioStatusBlock;
} tFileForReading;

BOOL FileForReading_Open(tFileForReading* pFile, PUNICODE_STRING FullModuleName)
{
	OBJECT_ATTRIBUTES  objAttr;

	InitializeObjectAttributes(&objAttr, FullModuleName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	
	

	// Do not try to perform any file operations at higher IRQL levels.
	// Instead, you may use a work item or a system worker thread to perform file operations.


	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return FALSE;

	NTSTATUS result = ZwCreateFile(&pFile->fileHandle,
		GENERIC_READ | SYNCHRONIZE,
		&objAttr, &pFile->ioStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);

	if (!NT_SUCCESS(result))
		return FALSE;

	return TRUE;
}

void FileForReading_Close(tFileForReading* pFile)
{
	if (pFile->fileHandle)
	{
		ZwClose(pFile->fileHandle);
		pFile->fileHandle = NULL;
	}
}

BOOL Module_RVA_toFileOffset(
	_In_ PVOID ModuleBaseAddress,
	_In_ DWORD requestedRVA,
	_In_ DWORD requestedSize,
	_Out_ ULONG* pFileOffset
)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBaseAddress;

	//Identify for valid PE file
	if (!dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		return FALSE;

	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((uintptr_t)(dosHeader)+(dosHeader->e_lfanew));

	//Identify for valid NT file
	if (!ntHeader->Signature == IMAGE_NT_SIGNATURE)
		return FALSE;

	// PIMAGE_OPTIONAL_HEADER opHeader = &ntHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(ntHeader);

	for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		if (requestedRVA >= pSecHeader->VirtualAddress
			&& requestedRVA < pSecHeader->VirtualAddress + pSecHeader->Misc.VirtualSize)
		{
			if (requestedRVA + requestedSize <= pSecHeader->VirtualAddress + pSecHeader->Misc.VirtualSize
				&& pSecHeader->PointerToRawData)
			{
				ULONG intoSectionFileOffset = requestedRVA - pSecHeader->VirtualAddress + pSecHeader->PointerToRawData;
				ULONG intoSectionFileOffsetEnd = intoSectionFileOffset + requestedSize;

				if (pSecHeader->PointerToRawData
					&& intoSectionFileOffsetEnd <= pSecHeader->PointerToRawData + pSecHeader->SizeOfRawData)
				{
					*pFileOffset = intoSectionFileOffset;
					return TRUE;
				}
			}

			return FALSE;
		}

		pSecHeader++;
	}

	return FALSE;
}

NTSTATUS
DriverEntryCode(
	_In_ PDRIVER_OBJECT     DriverObject,
	_In_ PUNICODE_STRING    RegistryPath
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = STATUS_SUCCESS;

	tFileForReading peFile = { 0 };
	char* pDVRTdata = NULL;

	unsigned int DbgPrintExIATindex = 0xFFFFFFFF;

	DbgPrint("driver entry\n");

	do
	{
		PLDR_DATA_TABLE_ENTRY pUSBXHCI_module = KernelGetModuleLdrEntry(DriverObject, "USBXHCI.SYS");

		PVOID USBXHCI_base = pUSBXHCI_module->ModuleBaseAddress;

		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)USBXHCI_base;

		//Identify for valid PE file
		if (!dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((uintptr_t)(dosHeader)+(dosHeader->e_lfanew));
		
		//Identify for valid NT file
		if (!ntHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		PIMAGE_OPTIONAL_HEADER opHeader = &ntHeader->OptionalHeader;

		IMAGE_DATA_DIRECTORY ImportsDirectory = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		if (!ImportsDirectory.VirtualAddress)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		IMAGE_DATA_DIRECTORY IATdirectory = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

		if (!IATdirectory.VirtualAddress)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		BOOL bLeaveLoop = FALSE;

		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((char*)USBXHCI_base + ImportsDirectory.VirtualAddress);

		while (pImportDescriptor->OriginalFirstThunk)
		{
			// LPCSTR LibraryName = (char*)USBXHCI_base + pImportDescriptor->Name;
			// DbgPrint("Library: %s pImportDescriptor: 0x%llX\n", LibraryName, pImportDescriptor);

			PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((char*)USBXHCI_base + pImportDescriptor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((char*)USBXHCI_base + pImportDescriptor->FirstThunk);

			PIMAGE_THUNK_DATA pOriginalThunk;
			PIMAGE_THUNK_DATA pThunk;

			unsigned int i = 0;

			while (TRUE)
			{

				pOriginalThunk = pOriginalFirstThunk + i;
				pThunk = pFirstThunk + i;

				unsigned int curIATindex = (pImportDescriptor->FirstThunk - IATdirectory.VirtualAddress) / sizeof(IMAGE_THUNK_DATA) + i;

				if (!pOriginalThunk->u1.AddressOfData)
					break;

				PIMAGE_IMPORT_BY_NAME imageImportByName = (PIMAGE_IMPORT_BY_NAME)((char*)USBXHCI_base + pOriginalThunk->u1.AddressOfData);
				LPCSTR functionName = (LPCSTR)&imageImportByName->Name;

				PVOID pFunctionAddress = (PVOID*)&pThunk->u1.Function;

				if (!strcmp(functionName, "DbgPrintEx"))
				{
					DbgPrintExIATindex = curIATindex;
					pDbgPrintFunctionAddress = pFunctionAddress;

					// DbgPrint("original function: 0x%llX\n", &pThunk->u1.Function);
					originalDbgPrint = (void*)pThunk->u1.Function;

					PVOID newFunctionAddress = (PVOID)&DbgPrintExReplacementForUSBXHCI;

					WriteMemory(pFunctionAddress, &newFunctionAddress, sizeof(newFunctionAddress), PAGE_EXECUTE_READ);

					bLeaveLoop = TRUE;
					break;
				}

				if (bLeaveLoop)
					break;

				i++;
				curIATindex++;
			}

			if (bLeaveLoop)
				break;

			pImportDescriptor++;
		}

		if (!pDbgPrintFunctionAddress)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (!opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress)
			break;

		windows_PIMAGE_LOAD_CONFIG_DIRECTORY pLoadConfig = (windows_PIMAGE_LOAD_CONFIG_DIRECTORY)((char*)USBXHCI_base + opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
		
		if (!pLoadConfig->GuardFlags & IMAGE_GUARD_RETPOLINE_PRESENT
			|| !pLoadConfig->DynamicValueRelocTableOffset)
			break;
		/////////////

		DWORD VirtualOffsetOfDVRT = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		if (!FileForReading_Open(&peFile, &pUSBXHCI_module->FullModuleName))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		LARGE_INTEGER      byteOffset = { 0 };

		Module_RVA_toFileOffset(
			USBXHCI_base,
			VirtualOffsetOfDVRT,
			sizeof(windows_IMAGE_DYNAMIC_RELOCATION_TABLE),
			&byteOffset.LowPart);

		windows_IMAGE_DYNAMIC_RELOCATION_TABLE DVRT_info;

		if (!NT_SUCCESS(ZwReadFile(peFile.fileHandle, NULL, NULL, NULL, &peFile.ioStatusBlock,
			&DVRT_info, sizeof(DVRT_info), &byteOffset, NULL)))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (DVRT_info.Version != 1)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		ULONG VirtualOffsetOfDVRTdata = VirtualOffsetOfDVRT + sizeof(windows_IMAGE_DYNAMIC_RELOCATION_TABLE);

		Module_RVA_toFileOffset(
			USBXHCI_base,
			VirtualOffsetOfDVRTdata,
			DVRT_info.Size,
			&byteOffset.LowPart);

		pDVRTdata = (char*)ExAllocatePoolWithTag(NonPagedPool, DVRT_info.Size, 'f92b');

		if (!NT_SUCCESS(ZwReadFile(peFile.fileHandle, NULL, NULL, NULL, &peFile.ioStatusBlock,
			pDVRTdata, DVRT_info.Size, &byteOffset, NULL)))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		
		unsigned int offsetIntoDVRT = 0;

		while (offsetIntoDVRT < DVRT_info.Size)
		{
			PIMAGE_DYNAMIC_RELOCATION pDVR = (PIMAGE_DYNAMIC_RELOCATION)(pDVRTdata + offsetIntoDVRT);


			if (pDVR->Symbol == IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER)
			{
				PIMAGE_BASE_RELOCATION pBaseR = (PIMAGE_BASE_RELOCATION)(pDVR + 1);
				unsigned int offsetIntoReloc = 0;

				while (offsetIntoReloc < pDVR->BaseRelocSize)
				{
					PIMAGE_BASE_RELOCATION pBaseRcur = (PIMAGE_BASE_RELOCATION)((char*)pBaseR + offsetIntoReloc);

					PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION pEntriesPerPage = (PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION)(pBaseRcur + 1);
					unsigned int CountOfEntriesPerPage = (pBaseRcur->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION);

					// DbgPrint("0x%X Virtual address: 0x%X Count of entries: %d\n", DbgPrintExIATindex,pBaseRcur->VirtualAddress, CountOfEntriesPerPage);

					ProcessRelocEntries((char*)USBXHCI_base + pBaseRcur->VirtualAddress, pEntriesPerPage, CountOfEntriesPerPage, DbgPrintExIATindex, pDbgPrintFunctionAddress);

					// DbgPrint("nn: 0x%X, 0x%X 0x%X count: %d\n", offsetIntoReloc, pBaseRcur->VirtualAddress, pBaseRcur->SizeOfBlock, CountOfEntriesPerPage);


					offsetIntoReloc += pBaseRcur->SizeOfBlock;
				}
			}

			offsetIntoDVRT += sizeof(IMAGE_DYNAMIC_RELOCATION) + pDVR->BaseRelocSize;
		}

		

		// DbgPrint("fdsafsa works: 0x%X\n", OffsetOfDVRT);

		// FileForReading_Close(&peFile);

		
		/*
		if (!opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
			break;

		windows_PIMAGE_DYNAMIC_RELOCATION_TABLE pDVRT = (windows_PIMAGE_DYNAMIC_RELOCATION_TABLE)((char*)USBXHCI_base
			+ opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			*/

// 		DbgPrint("fastman92 system bug fix: 0x%llX 0x%llX\n", USBXHCI_base, pDVRT);
	}
	while (FALSE);

	// NTSTATUS variable to record success or failure

	if (pDVRTdata)
		ExFreePool(pDVRTdata);

	FileForReading_Close(&peFile);

	DriverObject->DriverUnload = &DriverUnload;
	
	return status;
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT     DriverObject,
	_In_ PUNICODE_STRING    RegistryPath
)
{
	 return DriverEntryCode(DriverObject, RegistryPath);
}