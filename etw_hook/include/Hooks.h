#pragma once
#include <ntddk.h>
#include <windef.h>




void imageLoadCallBack(PUNICODE_STRING fullImageName, HANDLE processID, PIMAGE_INFO imageInfo);
NTSTATUS HookedNtQuerySystemInformationEx(ULONG SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS HookedNtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS HookedNtOpenProcess(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId OPTIONAL);
HANDLE  HookedNtQueryUserWindow(HANDLE WindowHandle, ULONG TypeInformation);
NTSTATUS hookedNtUserBuildHwndList(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize);
HWND HookedNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType);
HWND HookedNtUserGetForegroundWindow();

typedef NTSTATUS(*PNtOpenProcess)(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId OPTIONAL);
typedef NTSTATUS(*PNtQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(*PNtQuerySystemInformationEx)(ULONG SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef HANDLE(*PNtQueryUserWindow)(HANDLE WindowHandle, ULONG TypeInformation);
typedef NTSTATUS(*PNtUserBuildHwndList)(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize);
typedef HWND(*PNtUserFindWindowEx)(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType);
typedef HWND(*PNtUserGetForegroundWindow)();



inline PNtOpenProcess OriginalNtOpenProcess = NULL;
inline PNtQuerySystemInformation OriginalNtQuerySystemInformation = NULL;
inline PNtQuerySystemInformationEx OriginalNtQuerySystemInformationEx = NULL;
inline PNtQueryUserWindow OriginalNtQueryUserWindow = NULL;
inline PNtUserBuildHwndList OriginalNtUserBuildHwndList = NULL;
inline PNtUserFindWindowEx OriginalNtUserFindWindowEx = NULL;
inline PNtUserGetForegroundWindow OriginalNtUserGetForegroundWindow = NULL;