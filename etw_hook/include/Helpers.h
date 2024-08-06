#pragma once
#include <ntifs.h>
#include <windef.h>
#include <cstdint>


//SSDT typedef
typedef struct _SERVICE_DESCRIPTOR_TABLE {
    PULONG32 ServiceTableBase;
    PULONG32  ServiceCounterTableBase;
    ULONG NumberOfServices;
    PUCHAR ParamTableBase;
} SERVICE_DESCRIPTOR_TABLE, * PSERVICE_DESCRIPTOR_TABLE;



namespace SSDT
{
    PSERVICE_DESCRIPTOR_TABLE GetSSDT();
    PSERVICE_DESCRIPTOR_TABLE GetSSDTShadow(PSERVICE_DESCRIPTOR_TABLE ssdt);
    ULONGLONG GetSSDTShadowAddress(PSERVICE_DESCRIPTOR_TABLE g_KeServiceDescriptorTableShadow, ULONG64 Index);
    ULONGLONG GetSSDTAddress(PSERVICE_DESCRIPTOR_TABLE g_KeServiceDescriptorTable, ULONG64 Index);


}
namespace Helpers
{
    NTSTATUS findNtOsKernel(PVOID& kernelBase, ULONG& modSize);
    uintptr_t scanPattern(uint8_t* base, const size_t size, char* pattern, char* mask, int patternSize);
    uintptr_t getImageSectionByName(PVOID imageBase, const char* sectionName, size_t* sizeOut);
    NTSTATUS getProcID(PUNICODE_STRING TargetProcessName, PHANDLE ProcessId);
}
