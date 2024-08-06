#include "Hooks.h"

void imageLoadCallBack(PUNICODE_STRING fullImageName, HANDLE processID, PIMAGE_INFO imageInfo)
{
    if (wcsstr(fullImageName->Buffer, L"Nexon\\Library\\maplestory\\appdata\\MapleStory.exe"))
    {
        KdPrint(("MemMan: Maplestory module has been loaded with the processID: %d\n", processID));
        maplestoryPID = processID;
    }
    else if (wcsstr(fullImageName->Buffer, L"\\Nexon\\Library\\maplestory\\appdata\\BlackCipher\\BlackCipher64.aes"))
    {
        KdPrint(("MemMan: BlackCipher module has been loaded with the processID: %d\n", processID));
        blackCipherPID = processID;

    }
    else if (wcsstr(fullImageName->Buffer, L"\\Nexon\\Library\\maplestory\\appdata\\BlackCipher\\BlackCall64.aes"))
    {
        KdPrint(("MemMan: BlackCall module has been loaded with the processID: %d\n", processID));
        blackCallPID = processID;
    }
}

