#include <crtdefs.h>
static wchar_t* blackListedProcesses[] =
{
	L"cheatengine-x86_64-SSE4-AVX2.exe",
	L"ProcessHacker.exe",
	L"MemManUM.exe"
	L"cmd.exe",
	L"conhost.exe"
};

static wchar_t* targets[] =
{
	L"BlackCipher64.aes",
	L"BlackCall64.aes",
	L"MapleStory.exe"
};
