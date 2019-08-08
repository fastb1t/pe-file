#include <iostream>
#include <windows.h>

// [FileIsExist]:
static bool FileIsExist(const char* szFileName)
{
    if (!szFileName || !szFileName[0])
    {
        return false;
    }

    WIN32_FIND_DATA wfd;
    memset(&wfd, 0, sizeof(WIN32_FIND_DATA));

    HANDLE hFile = FindFirstFileA(szFileName, &wfd);
    if (hFile)
    {
        FindClose(hFile);
        return true;
    }
    return false;
}
// [/FileIsExist]


// [main]:
int main(int argc, char* argv[])
{
    std::string pe_file;
    std::string dll_name;
    std::string func_name;

    IMAGE_DOS_HEADER* mz_head = nullptr;
    IMAGE_FILE_HEADER* pe_head = nullptr;
    IMAGE_OPTIONAL_HEADER* pe_opt_head = nullptr;
    IMAGE_SECTION_HEADER* sect = nullptr;

    if (argc != 4)
    {
        std::cout
            << "\n Usage:"
            << "\n   pe-file.exe"
            << "\n      [*.exe || *.dll]  - input PE file"
            << "\n      [*.dll]           - will be added to the import table"
            << "\n      [function]        - imported function"
            << "\n";
        return EXIT_FAILURE;
    }

    std::cout << "\n";

    pe_file = argv[1];
    dll_name = argv[2];
    func_name = argv[3];

    if (pe_file.empty() || dll_name.empty() || func_name.empty())
    {
        std::cerr << "[ - ] Syntax error.\n";
        return EXIT_FAILURE;
    }

    if (!FileIsExist(pe_file.c_str()))
    {
        std::cerr << "[ - ] File '" << pe_file << "' not found.\n";
        return EXIT_FAILURE;
    }

    std::cout << "PE file:   " << pe_file << "\n";
    std::cout << "DLL:       " << dll_name << "\n";
    std::cout << "Function:  " << func_name << "\n";
    std::cout << "\n";


    HANDLE hFile = CreateFileA(
        pe_file.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (!hFile)
    {
        std::cerr << "[ - ] CreateFileA failed.\n";
        return EXIT_FAILURE;
    }

    HANDLE hFileMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hFileMap)
    {
        std::cerr << "[ - ] CreateFileMappingA failed.\n";
        CloseHandle(hFile);
        return EXIT_FAILURE;
    }
    CloseHandle(hFile);

    LPVOID pFileBegin = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, sizeof(IMAGE_DOS_HEADER));
    if (!pFileBegin)
    {
        std::cerr << "[ - ] MapViewOfFile failed.\n";
        CloseHandle(hFileMap);
        return EXIT_FAILURE;
    }


    mz_head = reinterpret_cast<IMAGE_DOS_HEADER*>(pFileBegin);
    DWORD dwPEOffset = mz_head->e_lfanew;
    UnmapViewOfFile(pFileBegin);

    int iSize = dwPEOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER);

    pFileBegin = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, iSize);
    if (!pFileBegin)
    {
        std::cerr << "[ - ] MapViewOfFile failed.\n";
        CloseHandle(hFileMap);
        return EXIT_FAILURE;
    }

    mz_head = reinterpret_cast<IMAGE_DOS_HEADER*>(pFileBegin);
    pe_head = reinterpret_cast<IMAGE_FILE_HEADER*>((DWORD)pFileBegin + dwPEOffset);


    char pe[] = "PE\0\0";
    if (lstrcmp(pe, (const char*)pe_head) != 0)
    {
        std::cerr << "[ - ] This file is not a PE file.\n";
        UnmapViewOfFile(pFileBegin);
        CloseHandle(hFileMap);
        return EXIT_FAILURE;
    }
    UnmapViewOfFile(pFileBegin);

    pFileBegin = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, 0);
    if (!pFileBegin)
    {
        std::cerr << "[ - ] MapViewOfFile failed.\n";
        CloseHandle(hFileMap);
        return EXIT_FAILURE;
    }


    mz_head = reinterpret_cast<IMAGE_DOS_HEADER*>(pFileBegin);
    pe_head = reinterpret_cast<IMAGE_FILE_HEADER*>((DWORD)pFileBegin + dwPEOffset + sizeof(DWORD));
    pe_opt_head = reinterpret_cast<IMAGE_OPTIONAL_HEADER*>((DWORD)pe_head + sizeof(IMAGE_FILE_HEADER));
    sect = reinterpret_cast<IMAGE_SECTION_HEADER*>((DWORD)pe_opt_head + sizeof(IMAGE_OPTIONAL_HEADER));

    DWORD dwImportRVA = pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    int iSectNum = -1;
    for (int i = 0; i < pe_head->NumberOfSections; i++)
    {
        if (dwImportRVA < sect->VirtualAddress)
        {
            sect--;
            iSectNum = i - 1;
            break;
        }
        sect++;
    }

    if (iSectNum == -1)
    {
        std::cerr << "[ - ] This program does not use dynamic libraries.\n";
        UnmapViewOfFile(pFileBegin);
        CloseHandle(hFileMap);
        return EXIT_FAILURE;
    }

    sect++;
    DWORD dwAfterImportSecBeg = (DWORD)pFileBegin + sect->PointerToRawData;
    sect--;

    LPVOID ImportSecBeg = reinterpret_cast<LPVOID>((DWORD)pFileBegin + sect->PointerToRawData);

    LPVOID ImportTable = reinterpret_cast<LPVOID>((DWORD)ImportSecBeg + (dwImportRVA - sect->VirtualAddress));

    IMAGE_IMPORT_DESCRIPTOR* DLLInfo = (IMAGE_IMPORT_DESCRIPTOR*)ImportTable;
    LPVOID DLLName = nullptr;
    DWORD dwDLLCounter = 0;

    while (DLLInfo->Name != NULL)
    {
        dwDLLCounter++;
        DLLName = reinterpret_cast<LPVOID>((DWORD)ImportSecBeg + ((DWORD)DLLInfo->Name - sect->VirtualAddress));

        std::cout << dwDLLCounter << " -> " << reinterpret_cast<char*>(DLLName) << "\n";

        DLLInfo++;
    }

    std::cout << "\nTotal DLL: " << dwDLLCounter << "\n";


    DWORD dwNewImportTableSize = sizeof(IMAGE_IMPORT_DESCRIPTOR) * (dwDLLCounter + 2);

    LPVOID pos = reinterpret_cast<LPVOID>(dwAfterImportSecBeg - 1);

    DWORD dwMaxFree = 0;
    DWORD dwPrevPtr = 0;
    LPVOID FreePtr = nullptr;

    while (pos >= ImportSecBeg)
    {
        if (*(BYTE*)pos == 0x00)
        {
            dwPrevPtr = (DWORD)pos;
            while (*(BYTE*)pos == 0x00)
            {
                pos = reinterpret_cast<LPVOID>((DWORD)pos - 1);
            }

            if (((DWORD)dwPrevPtr - (DWORD)pos) > dwMaxFree)
            {
                dwMaxFree = ((DWORD)dwPrevPtr - (DWORD)pos);
                FreePtr = reinterpret_cast<LPVOID>((DWORD)pos + 1);
            }
        }
        pos = reinterpret_cast<LPVOID>((DWORD)pos - 1);
    }

    FreePtr = reinterpret_cast<LPVOID>((DWORD)FreePtr + 1);
    dwMaxFree -= 4;

    if (dwMaxFree < dwNewImportTableSize)
    {
        std::cerr << "[ - ] No free space in the import table.\n";
        UnmapViewOfFile(pFileBegin);
        CloseHandle(hFileMap);
        return EXIT_FAILURE;
    }


    memcpy(FreePtr, ImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR) * dwDLLCounter);
    memcpy(ImportTable, dll_name.c_str(), dll_name.length());

    LPDWORD lpdwZeroPtr = reinterpret_cast<LPDWORD>((DWORD)ImportTable + dll_name.length());

    IMAGE_IMPORT_BY_NAME myName;
    myName.Hint = 0x00;
    myName.Name[0] = 0x00;

    typedef struct {
        DWORD dwZeroDword;
        DWORD dwIAT;
        DWORD dwIATEnd;
    } NRecord;

    NRecord patch;
    patch.dwZeroDword = NULL;
    patch.dwIAT = dwImportRVA + static_cast<DWORD>(dll_name.length()) + sizeof(NRecord);
    patch.dwIATEnd = NULL;

    WORD wHint = 0;

    memcpy(lpdwZeroPtr, &patch, sizeof(patch));
    lpdwZeroPtr = reinterpret_cast<LPDWORD>((DWORD)lpdwZeroPtr + sizeof(patch));
    memcpy(lpdwZeroPtr, &wHint, sizeof(WORD));
    lpdwZeroPtr = reinterpret_cast<LPDWORD>((DWORD)lpdwZeroPtr + sizeof(WORD));
    memcpy(lpdwZeroPtr, func_name.c_str(), func_name.length() + 1);
    lpdwZeroPtr = reinterpret_cast<LPDWORD>((DWORD)lpdwZeroPtr + func_name.length() + 1);
    memcpy(lpdwZeroPtr, &myName, sizeof(IMAGE_IMPORT_BY_NAME));


    DWORD dwIIBN_Table = dwImportRVA + static_cast<DWORD>(dll_name.length()) + sizeof(DWORD);

    IMAGE_IMPORT_DESCRIPTOR myDLL;
    myDLL.Characteristics = dwIIBN_Table;
    myDLL.TimeDateStamp = NULL;
    myDLL.ForwarderChain = NULL;
    myDLL.Name = dwImportRVA;
    myDLL.FirstThunk = dwIIBN_Table;

    LPVOID OldFreePtr = FreePtr;
    FreePtr = reinterpret_cast<LPVOID>((DWORD)FreePtr + sizeof(IMAGE_IMPORT_DESCRIPTOR) * dwDLLCounter);

    memcpy(FreePtr, &myDLL, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    myDLL.Characteristics = NULL;
    myDLL.TimeDateStamp = NULL;
    myDLL.ForwarderChain = NULL;
    myDLL.Name = NULL;
    myDLL.FirstThunk = NULL;

    FreePtr = reinterpret_cast<LPVOID>((DWORD)FreePtr + sizeof(IMAGE_IMPORT_DESCRIPTOR) * dwDLLCounter);

    memcpy(FreePtr, &myDLL, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    DWORD dwNewImportTableRVA = (DWORD)OldFreePtr - (DWORD)ImportSecBeg + sect->VirtualAddress;

    pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = dwNewImportTableRVA;
    pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (dwDLLCounter + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
    pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
    pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;

    UnmapViewOfFile(pFileBegin);
    CloseHandle(hFileMap);

    std::cout << "\nDone!\n";
    return EXIT_SUCCESS;
}
// [/main]
