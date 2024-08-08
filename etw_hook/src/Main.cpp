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

	status = EtwHookManager::get_instance()->init();
	HANDLE ProcessId;
	PEPROCESS Process{};

	UNICODE_STRING targetProcess;
	RtlInitUnicodeString(&targetProcess, L"winlogon.exe");
	Helpers::FindProcessIdByName(&targetProcess, &ProcessId);
	PsLookupProcessByProcessId(ProcessId, &Process);
	KAPC_STATE oldApc;
	KeStackAttachProcess(Process, &oldApc);

	ssdtTable = SSDT::GetSSDT();
	ssdtShadowTable = SSDT::GetSSDTShadow(ssdtTable);

	OriginalNtOpenProcess = (PNtOpenProcess)SSDT::GetSSDTAddress(ssdtTable, SSDT::getSSDTIndex(NtOpenProcessID));
	OriginalNtQuerySystemInformation = (PNtQuerySystemInformation)SSDT::GetSSDTAddress(ssdtTable, SSDT::getSSDTIndex(NtQuerySystemInformationID));
	OriginalNtUserBuildHwndList = (PNtUserBuildHwndList)SSDT::GetSSDTShadowAddress(ssdtShadowTable, SSDT::getSSDTIndex(NtUserBuildHwndListID));
	OriginalNtUserQueryWindow = (PNtUserQueryWindow)SSDT::GetSSDTShadowAddress(ssdtShadowTable, SSDT::getSSDTIndex(NtUserQueryWindowID));
	OriginalNtUserFindWindowEx = (PNtUserFindWindowEx)SSDT::GetSSDTShadowAddress(ssdtShadowTable, SSDT::getSSDTIndex(NtUserFindWindowExID));
	OriginalNtUserGetForegroundWindow = (PNtUserGetForegroundWindow)SSDT::GetSSDTShadowAddress(ssdtShadowTable, SSDT::getSSDTIndex(NtUserGetForegroundWindowID));

	KeUnstackDetachProcess(&oldApc);

	EtwHookManager::get_instance()->add_hook(OriginalNtOpenProcess, Hooks::HookedNtOpenProcess);
	EtwHookManager::get_instance()->add_hook(OriginalNtQuerySystemInformation, Hooks::HookedNtQuerySystemInformation);
	EtwHookManager::get_instance()->add_hook(OriginalNtUserQueryWindow, Hooks::HookedNtUserQueryWindow);
	EtwHookManager::get_instance()->add_hook(OriginalNtUserBuildHwndList, Hooks::HookedNtUserBuildHwndList);
	EtwHookManager::get_instance()->add_hook(OriginalNtUserFindWindowEx, Hooks::HookedNtUserFindWindowEx);
	EtwHookManager::get_instance()->add_hook(OriginalNtUserGetForegroundWindow, Hooks::HookedNtUserGetForegroundWindow);

	

	return status;
}