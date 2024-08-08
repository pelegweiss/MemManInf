#include "Hooks.h"
#include "Helpers.h"



HANDLE Hooks::HookedNtUserQueryWindow(HANDLE hWnd, ULONG WindowInfo)
{
    HANDLE targetPid = OriginalNtUserQueryWindow(hWnd, WindowInfo);

    PEPROCESS sourceProcess = PsGetCurrentProcess();
    HANDLE sourceProcessId = PsGetProcessId(sourceProcess);

    if (!Helpers::IsTargetProcess(sourceProcessId))
        return targetPid;



    if (Helpers::IsBlackListedProcess(targetPid))
    {
        UNICODE_STRING targetName = { 0 };
        // Retrieve the target process name
        if (!(Helpers::GetProcessNameFromPID(targetPid, &targetName)))
        {
            // Log an error and return the original PID if process name retrieval fails
            KdPrint(("MemMan: Failed to get process name for PID: %p from HookedNtQueryUserWindow\n", targetPid));
            return targetPid;
        }

        KdPrint(("MemMan: Stripping out :%wZ from UserQueryWindow\n", targetName));
        return 0;
    }

    return targetPid;
}
NTSTATUS Hooks::HookedNtUserBuildHwndList(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize)
{

    NTSTATUS status = OriginalNtUserBuildHwndList(hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);
    PEPROCESS sourceProcess = PsGetCurrentProcess();
    HANDLE sourceProcessId = PsGetProcessId(sourceProcess);
    if (!Helpers::IsTargetProcess(sourceProcessId))
        return status;
    if (NT_SUCCESS(status) && pWnd != NULL && pBufSize != NULL)
    {
        ULONG count = *pBufSize;
        ULONG newCount = 0;
        for (ULONG i = 0; i < count; ++i)
        {


            if (pWnd[i]) //strip out the process
            {
                HANDLE targetPid = 0;
                targetPid = OriginalNtUserQueryWindow(pWnd[i], 0);

                if (Helpers::IsBlackListedProcess(targetPid))
                {
                    UNICODE_STRING targetName = { 0 };
                    // Retrieve the target process name
                    if (!(Helpers::GetProcessNameFromPID(targetPid, &targetName)))
                    {
                        // Log an error and return the original PID if process name retrieval fails
                        KdPrint(("MemMan: Failed to get process name for PID: %p from hookedNtUserBuildHwndList\n", targetPid));
                        return status;
                    }
                    KdPrint(("MemMan: Stripping out window of process:%wZ from the windows list\n", targetName));
                    for (ULONG j = i; j < count - 1; j++)
                    {
                        pWnd[j] = pWnd[j + 1];
                    }
                    count--;
                    i--; // Adjust index to account for the removed element
                }

            }
        }
        *pBufSize = count;
    }

    return status;
}
NTSTATUS Hooks::HookedNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
    NTSTATUS status = OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    PEPROCESS sourceProcess = PsGetCurrentProcess();
    HANDLE sourceProcessId = PsGetProcessId(sourceProcess);
    if(!Helpers::IsTargetProcess(sourceProcessId))
        return status;

    HANDLE targetProcessId = NULL;

    // Determine the target process ID
    if (ClientId) {
        targetProcessId = ClientId->UniqueProcess;
    }
    else if (ObjectAttributes && ObjectAttributes->ObjectName) {
        PUNICODE_STRING objectName = ObjectAttributes->ObjectName;

        // Extract the process ID from the object name if possible
        UNICODE_STRING pidString;
        RtlInitUnicodeString(&pidString, objectName->Buffer);

        ULONG pidValue;
        status = RtlUnicodeStringToInteger(&pidString, 10, &pidValue);
        if (NT_SUCCESS(status)) {
            targetProcessId = (HANDLE)(ULONG_PTR)pidValue;
        }
    }

    if (targetProcessId)
    {
        if (Helpers::IsBlackListedProcess(targetProcessId))
        {
            UNICODE_STRING targetName = { 0 };
            // Retrieve the target process name
            if (!(Helpers::GetProcessNameFromPID(targetProcessId, &targetName)))
            {
                // Log an error and return the original PID if process name retrieval fails
                KdPrint(("MemMan: Failed to get process name for PID: %p from HookedNtQueryUserWindow\n", targetProcessId));
                return status;
            }
            UNICODE_STRING sourceName;
            if (!(Helpers::GetProcessNameFromPID(sourceProcessId, &sourceName)))
            {
                // Log an error and return the original PID if process name retrieval fails
                KdPrint(("MemMan: Failed to get process name for PID: %p from HookedNtQueryUserWindow\n", sourceProcessId));
                return status;
            }
            KdPrint(("MemMan: Prevented handle creation from process %wZ to process %wZ\n", sourceName, targetName));
            return STATUS_ACCESS_DENIED;
        }
    }
    return status;
}
NTSTATUS HideProtectedProcesses(PVOID SystemInformation) {
    PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
    PSYSTEM_PROCESS_INFORMATION pPrevious = NULL;


    while (pCurrent) {

        if (Helpers::IsBlackListedProcess(pCurrent->UniqueProcessId))
        {
            UNICODE_STRING processName;
            Helpers::GetProcessNameFromPID(pCurrent->UniqueProcessId, &processName);
            KdPrint(("MemMan: Stripping out Process %wZ from processes list \n", processName));

            if (pPrevious) {
                if (pCurrent->NextEntryOffset) {
                    pPrevious->NextEntryOffset += pCurrent->NextEntryOffset;
                }
                else {
                    pPrevious->NextEntryOffset = 0;
                }
            }
            else {
                // If the first entry is protected, move the start of the list
                SystemInformation = (PVOID)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
            }
        }
        else {
            pPrevious = pCurrent;
        }

        if (pCurrent->NextEntryOffset) {
            pCurrent = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
        }
        else {
            break;
        }
    }

    return STATUS_SUCCESS;
}
NTSTATUS HideProtectedHandles(PSYSTEM_HANDLE_INFORMATION HandleInfo) {

    ULONG newCount = 0;
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO pHandle = HandleInfo->Handles;

    for (ULONG i = 0; i < HandleInfo->NumberOfHandles; i++)
    {

        if (Helpers::IsBlackListedProcess(ULongToHandle(pHandle[i].UniqueProcessId)))
        {
            //LOG_INFO("Hidden handles from process %wZ\n", processName);
            if (i != newCount)
                RtlCopyMemory(&pHandle[newCount], &pHandle[i], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
            newCount++;
        }

    }
    HandleInfo->NumberOfHandles = newCount;
    return STATUS_SUCCESS;
}
NTSTATUS HideProtectedHandlesEx(PSYSTEM_HANDLE_INFORMATION_EX HandleInfo) 
{
    ULONG64 newCount = 0;
    for (ULONG64 i = 0; i < HandleInfo->HandleCount; i++) {
        if (Helpers::IsBlackListedProcess(HandleInfo->Handles[i].UniqueProcessId))
        {
            {
                //LOG_INFO("Hiding handles of process %wZ from query\n", processName);
                if (i != newCount)
                    RtlCopyMemory(&HandleInfo->Handles[newCount], &HandleInfo->Handles[i], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                newCount++;
            }
        }
    }
    HandleInfo->HandleCount = newCount;
    return STATUS_SUCCESS;
}
NTSTATUS ModifyDebuggerInfo(PSYSTEM_KERNEL_DEBUGGER_INFORMATION DebuggerInfo) {
    //LOG_INFO("Hiding debugger infomration\n");
    DebuggerInfo->KernelDebuggerEnabled = FALSE;
    DebuggerInfo->KernelDebuggerNotPresent = TRUE;
    return STATUS_SUCCESS;
};
NTSTATUS Hooks::HookedNtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
  
    NTSTATUS status = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    PEPROCESS sourceProcess = PsGetCurrentProcess();
    HANDLE sourceProcessId = PsGetProcessId(sourceProcess);
    if (!NT_SUCCESS(status) || SystemInformation == NULL) {
        return status;
    }
    if (!Helpers::IsTargetProcess(sourceProcessId))
        return status;
    switch (SystemInformationClass)
    {
    case SystemProcessInformation:
    case SystemSessionProcessInformation:
    case SystemExtendedProcessInformation:
        status = HideProtectedProcesses(SystemInformation);
        break;
    case SystemHandleInformation:
        status = HideProtectedHandles((PSYSTEM_HANDLE_INFORMATION)SystemInformation);
        break;
    case SystemExtendedHandleInformation:
        status = HideProtectedHandlesEx((PSYSTEM_HANDLE_INFORMATION_EX)SystemInformation);
        break;
    case 35: //SystemKernelDebuggerInformation
        status = ModifyDebuggerInfo((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation);
        break;
    default:
        break;
    }
    return status;
}
HWND Hooks::HookedNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType)
{
    const auto res = OriginalNtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);
    PEPROCESS sourceProcess = PsGetCurrentProcess();
    HANDLE sourceProcessId = PsGetProcessId(sourceProcess);

    if (!Helpers::IsTargetProcess(sourceProcessId))
        return res;

    if (res)
    {
        auto targetPid = OriginalNtUserQueryWindow(res, 0);

        if (Helpers::IsBlackListedProcess(targetPid))
        {
            UNICODE_STRING targetName = { 0 };
            // Retrieve the target process name
            if (!(Helpers::GetProcessNameFromPID(targetPid, &targetName)))
            {
                // Log an error and return the original PID if process name retrieval fails
                KdPrint(("MemMan: Failed to get process name for PID: %p\n from HookedNtUserFindWindowEx", targetPid));
                return res;
            }
            KdPrint(("MemMan: Stripping out process: %wZ from UserFindWindow\n", &targetName));
            return NULL;
        }


    }
    return res;
}

HWND LastForeWnd = HWND(-1);
HWND Hooks::HookedNtUserGetForegroundWindow()
{
    HWND res = OriginalNtUserGetForegroundWindow();
    PEPROCESS sourceProcess = PsGetCurrentProcess();
    HANDLE sourceProcessId = PsGetProcessId(sourceProcess);
    if (!Helpers::IsTargetProcess(sourceProcessId))
    {
        LastForeWnd = res;
        return res;
    }

    HANDLE targetPid = 0;
    targetPid = OriginalNtUserQueryWindow(res, 0);


    if (Helpers::IsBlackListedProcess(targetPid))
    {
        UNICODE_STRING targetName = { 0 };
        // Retrieve the target process name
        if (!(Helpers::GetProcessNameFromPID(targetPid, &targetName)))
        {
            // Log an error and return the original PID if process name retrieval fails
            KdPrint(("MemMan: Failed to get process name for PID: %p from hookedNtUserBuildHwndList\n", targetPid));
            return res;
        }
        KdPrint(("MemMan: Hiding window %wZ from the foreground\n", targetName));
        return LastForeWnd;
    }
    return res;

}
