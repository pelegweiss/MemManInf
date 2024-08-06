#include "Helpers.h"
#include "Blacklist.h"

#define SystemModuleInformation 11
#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.


typedef struct _IMAGE_DOS_HEADER {
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _IMAGE_FILE_HEADER {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	ULONGLONG ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Win32VersionValue;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	ULONGLONG SizeOfStackReserve;
	ULONGLONG SizeOfStackCommit;
	ULONGLONG SizeOfHeapReserve;
	ULONGLONG SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;



typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
	BYTE  Name[8];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD NumberOfRelocations;
	WORD NumberOfLinenumbers;
	DWORD Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;


#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER) \
    ((ULONG_PTR)(ntheader) +                                     \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +        \
     ((ntheader))->FileHeader.SizeOfOptionalHeader))


typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;



extern "C" {
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
	NTKERNELAPI NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	inline NTKERNELAPI NTSTATUS ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation,ULONG SystemInformationLength, PULONG ReturnLength);
}


NTSTATUS Helpers::findNtOsKernel(PVOID& kernelBase, ULONG& modSize)
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bytes);
	if (bytes == 0) {
		return STATUS_INVALID_PARAMETER;
	}

	PSYSTEM_MODULE_INFORMATION pMods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, 'ARMS');
	if (!pMods) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);
	if (!NT_SUCCESS(status)) {
		ExFreePool(pMods);
		return STATUS_INVALID_PARAMETER;
	}

	kernelBase = (pMods->Module[0].ImageBase);
	modSize = pMods->Module[0].ImageSize;
	ExFreePool(pMods);
	return STATUS_SUCCESS;
}

PSERVICE_DESCRIPTOR_TABLE SSDT::GetSSDT() {
	PVOID ntoskrnlBase{};
	ULONG ntoskrnlSize{};
	if (!NT_SUCCESS(Helpers::findNtOsKernel(ntoskrnlBase, ntoskrnlSize)))
		return 0;
	if (!ntoskrnlBase)
		return 0;
	size_t ntoskrnlTextSize{};
	const auto ntoskrnlText = Helpers::getImageSectionByName(ntoskrnlBase, ".text", &ntoskrnlTextSize);
	if (!ntoskrnlText)
		return {};

	auto keServiceDescriptorTableShadow = Helpers::scanPattern(reinterpret_cast<BYTE*>(ntoskrnlText), ntoskrnlTextSize,
		"\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F", "xxxxxxxxx", 9);

	if (!keServiceDescriptorTableShadow)
		return {};

	keServiceDescriptorTableShadow += 21;
	keServiceDescriptorTableShadow += *reinterpret_cast<std::int32_t*>(keServiceDescriptorTableShadow) + sizeof(std::int32_t);

	return PSERVICE_DESCRIPTOR_TABLE(keServiceDescriptorTableShadow);

}
PSERVICE_DESCRIPTOR_TABLE SSDT::GetSSDTShadow(PSERVICE_DESCRIPTOR_TABLE ssdt)
{
	return (PSERVICE_DESCRIPTOR_TABLE)((ULONG_PTR)ssdt + 0x20);
}

uintptr_t Helpers::scanPattern(uint8_t* base, const size_t size, char* pattern, char* mask, int patternSize) {

	for (size_t i = {}; i < size - patternSize; i++)
	{
		for (size_t j = {}; j < patternSize; j++)
		{
			if (mask[j] != '?' && *reinterpret_cast<uint8_t*>(base + i + j) != static_cast<uint8_t>(pattern[j]))
				break;

			if (j == patternSize - 1)
				return reinterpret_cast<uintptr_t>(base) + i;
		}
	}

	return {};
}

uintptr_t Helpers::getImageSectionByName(PVOID imageBase, const char* sectionName, size_t* sizeOut)
{
	if (!imageBase)
		return 0;
	PIMAGE_DOS_HEADER pImage = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
	if (pImage->e_magic != 0x5A4D)
		return {};
	PIMAGE_NT_HEADERS64 ntHeader{};
	ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(
		(uintptr_t)imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
	const auto sectionCount = ntHeader->FileHeader.NumberOfSections;

	auto sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
	for (size_t i{}; i < sectionCount; ++i, ++sectionHeader) {
		if (!strcmp(sectionName, reinterpret_cast<const char*>(sectionHeader->Name))) {
			if (sizeOut)
				*sizeOut = sectionHeader->Misc.VirtualSize;
			return (uintptr_t)imageBase + sectionHeader->VirtualAddress;
		}
	}

	return {};
}

ULONGLONG SSDT::GetSSDTShadowAddress(PSERVICE_DESCRIPTOR_TABLE g_KeServiceDescriptorTableShadow, ULONG64 Index)
{
	ULONGLONG	W32pServiceTable = 0, qwTemp = 0;
	LONG 	dwTemp = 0;
	W32pServiceTable = (ULONGLONG)(g_KeServiceDescriptorTableShadow->ServiceTableBase);
	qwTemp = W32pServiceTable + 4 * (Index - 0x1000);
	dwTemp = *(PLONG)qwTemp;
	dwTemp = dwTemp >> 4;
	qwTemp = W32pServiceTable + (LONG64)dwTemp;
	return qwTemp;
}
ULONGLONG SSDT::GetSSDTAddress(PSERVICE_DESCRIPTOR_TABLE g_KeServiceDescriptorTable, ULONG64 Index)
{
	return (ULONGLONG)(g_KeServiceDescriptorTable->ServiceTableBase) + (g_KeServiceDescriptorTable->ServiceTableBase[Index] >> 4);
}

NTSTATUS Helpers::getProcID(PUNICODE_STRING TargetProcessName, PHANDLE ProcessId) {
	NTSTATUS status;
	PVOID buffer;
	ULONG bufferSize = 0x10000; // Initial buffer size

	buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'proc');
	if (!buffer) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Query process information
	while ((status = ZwQuerySystemInformation(5, buffer, bufferSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
		ExFreePoolWithTag(buffer, 'proc');
		bufferSize *= 2;
		buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'proc');
		if (!buffer) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(buffer, 'proc');
		return status;
	}

	// Iterate over the processes
	PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
	while (TRUE) {
		if (processInfo->ImageName.Length > 0 && RtlCompareUnicodeString(&processInfo->ImageName, TargetProcessName, TRUE) == 0) {
			*ProcessId = processInfo->UniqueProcessId;
			ExFreePoolWithTag(buffer, 'proc');
			return STATUS_SUCCESS;
		}
		if (processInfo->NextEntryOffset == 0) {
			break;
		}
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
	}

	ExFreePoolWithTag(buffer, 'proc');
	return STATUS_NOT_FOUND;
}

BOOLEAN Helpers::GetProcessNameFromPID(HANDLE pid, PUNICODE_STRING processName) {
	PEPROCESS process;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) {
		return FALSE;
	}

	PUNICODE_STRING imageFileName;
	NTSTATUS status = SeLocateProcessImageName(process, &imageFileName);

	if (NT_SUCCESS(status)) {
		status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, imageFileName, processName);
		ExFreePool(imageFileName);
	}

	return NT_SUCCESS(status);
}

BOOLEAN Helpers::IsBlackListedProcess(HANDLE sourcePID)
{
	for (int i = 0; i < ARRAYSIZE(blackListedProcesses); i++)
	{
		HANDLE bufferPID;
		UNICODE_STRING buffer;
		RtlInitUnicodeString(&buffer, blackListedProcesses[i]);
		if (NT_SUCCESS(Helpers::getProcID(&buffer, &bufferPID)))	
		{
			if (bufferPID == sourcePID)
			{
				return TRUE;
			}
		}

			
	}
	return FALSE;
}


NTSTATUS Helpers::FindProcessIdByName(PUNICODE_STRING TargetProcessName, PHANDLE ProcessId) {
	NTSTATUS status;
	PVOID buffer;
	ULONG bufferSize = 0x10000; // Initial buffer size

	buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'proc');
	if (!buffer) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Query process information
	while ((status = ZwQuerySystemInformation(5, buffer, bufferSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
		ExFreePoolWithTag(buffer, 'proc');
		bufferSize *= 2;
		buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'proc');
		if (!buffer) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(buffer, 'proc');
		return status;
	}

	// Iterate over the processes
	PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
	while (TRUE) {
		if (processInfo->ImageName.Length > 0 && RtlCompareUnicodeString(&processInfo->ImageName, TargetProcessName, TRUE) == 0) {
			*ProcessId = processInfo->UniqueProcessId;
			ExFreePoolWithTag(buffer, 'proc');
			return STATUS_SUCCESS;
		}
		if (processInfo->NextEntryOffset == 0) {
			break;
		}
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
	}

	ExFreePoolWithTag(buffer, 'proc');
	return STATUS_NOT_FOUND;
}
