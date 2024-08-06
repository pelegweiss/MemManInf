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

	PsSetLoadImageNotifyRoutine(imageLoadCallBack);
	status = EtwHookManager::get_instance()->init(drv, imageLoadCallBack);

	ssdtTable = SSDT::GetSSDT();
	ssdtShadowTable = SSDT::GetSSDTShadow(ssdtTable);

	return status;
}