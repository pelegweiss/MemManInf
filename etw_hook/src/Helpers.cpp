#include "Helpers.h"
#include "Structures.h"
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
