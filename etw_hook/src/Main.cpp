#include <refs.hpp>
#include <etwhook_init.hpp>
#include <etwhook_manager.hpp>
#include <kstl/ksystem_info.hpp>
#include "Hooks.h"
#include "Helpers.h"



PSERVICE_DESCRIPTOR_TABLE ssdtTable, ssdtShadowTable;

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT drv,PUNICODE_STRING)
{
	auto status = STATUS_SUCCESS;
	
	drv->DriverUnload = [](PDRIVER_OBJECT) {

		EtwHookManager::get_instance()->destory();
	};
	
	kstd::Logger::init("etw_hook", nullptr);

	KdPrint(("MemMan: Init...\n"));

	status = EtwHookManager::get_instance()->init(drv);

	ssdtTable = SSDT::GetSSDT();
	ssdtShadowTable = SSDT::GetSSDTShadow(ssdtTable);

	OriginalNtOpenProcess = (PNtOpenProcess)SSDT::GetSSDTAddress(ssdtTable, 0x26);
	OriginalNtQuerySystemInformation = (PNtQuerySystemInformation)SSDT::GetSSDTAddress(ssdtTable, 0x36);

	EtwHookManager::get_instance()->add_hook(OriginalNtOpenProcess, Hooks::HookedNtOpenProcess);
	EtwHookManager::get_instance()->add_hook(OriginalNtQuerySystemInformation, Hooks::HookedNtQuerySystemInformation);


	return status;
}