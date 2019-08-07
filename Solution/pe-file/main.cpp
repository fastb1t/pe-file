#include <iostream>
#include <windows.h>

// [ParseError]:
void ParseError()
{
    char* msg = nullptr;
    if (FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        GetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language.
        (LPTSTR)& msg,
        0,
        NULL
    ) != 0)
    {
        if (msg != nullptr)
        {
            std::cerr << "[ - ] " << msg << "\n";
            delete[] msg;
        }
    }
}
// [/ParseError]


// [FileIsExist]:
bool FileIsExist(const char* szFileName)
{
    if (szFileName == nullptr || szFileName[0] == 0)
    {
        return false;
    }

    WIN32_FIND_DATA wfd;
    HANDLE hFile = FindFirstFile(szFileName, &wfd);
    if (hFile != INVALID_HANDLE_VALUE)
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
    if (argc != 4)
    {
        std::cout
            << "\n Usage:"
            << "\n   pe-file[64].exe"
            << "\n      [*.exe || *.dll]  - input PE file"
            << "\n      [*.dll]           - will be added to the import table"
            << "\n      [function]        - imported function"
            << "\n";
        return EXIT_FAILURE;
    }

    std::cout << "\n";

    std::string pe_file = argv[1];
    std::string dll_name = argv[2];
    std::string func_name = argv[3];

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

    setlocale(LC_ALL, "Russian");

    std::cout << "PE file:   " << pe_file << "\n";
    std::cout << "DLL:       " << dll_name << "\n";
    std::cout << "Function:  " << func_name << "\n";
    std::cout << "\n";

    typedef struct {
        DWORD ZeroDword;
        DWORD IAT;
        DWORD IATEnd;
    } hackRec;

    IMAGE_DOS_HEADER* mz_head;
    IMAGE_FILE_HEADER* pe_head;
    IMAGE_OPTIONAL_HEADER* pe_opt_head;
    IMAGE_SECTION_HEADER* sect;
    

    HANDLE hFile = CreateFile(pe_file.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Ошибка при открытии файла: ";
        ParseError();
        return EXIT_FAILURE;
    }

    HANDLE hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    CloseHandle(hFile);

    if (hFileMap == NULL)
    {
        std::cerr << "Ошибка при вызове CreateFileMapping(): ";
        ParseError();
        return 1;
    }

    int size = sizeof(IMAGE_DOS_HEADER);

    LPVOID fBeg = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, size);
    if (fBeg == NULL)
    {
        std::cerr << "Ошибка при вызове MapViewOfFile(): ";
        ParseError();
        return 1;
    }

    // Определяем смещение РЕ-заголовка.
    mz_head = reinterpret_cast<IMAGE_DOS_HEADER*>(fBeg);
    DWORD peOffset = mz_head->e_lfanew;
    UnmapViewOfFile(fBeg);

    // Отображаем в память с учетом смещения до РЕ-заголовка.
    size = peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER);

    fBeg = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, size);
    if (fBeg == NULL)
    {
        std::cerr << "Ошибка при вызове MapViewOfFile(): ";
        ParseError();
        CloseHandle(hFileMap);
        return 1;
    }

    mz_head = reinterpret_cast<IMAGE_DOS_HEADER*>(fBeg);
    pe_head = reinterpret_cast<IMAGE_FILE_HEADER*>((DWORD)fBeg + peOffset);


    // Проверяем, PE или не PE файл.
    char pe[] = "PE\0\0";
    if (strcmp(pe, (const char*)pe_head) != 0)
    {
        std::cerr << "Этот файл не является Portable Executable - файлом.\n";
        UnmapViewOfFile(fBeg);
        CloseHandle(hFileMap);
        return 1;
    }
    UnmapViewOfFile(fBeg);

    // По новой отображаем файл в память поностью.
    fBeg = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, 0);
    if (fBeg == NULL)
    {
        std::cerr << "Ошибка при вызове MapViewOfFile(): ";
        ParseError();
        CloseHandle(hFileMap);
        return 1;
    }


    mz_head = reinterpret_cast<IMAGE_DOS_HEADER*>(fBeg);
    pe_head = reinterpret_cast<IMAGE_FILE_HEADER*>((DWORD)fBeg + peOffset + sizeof(DWORD));
    pe_opt_head = reinterpret_cast<IMAGE_OPTIONAL_HEADER*>((DWORD)pe_head + sizeof(IMAGE_FILE_HEADER));


    // Определяем расположение таблицы импорта в секции импорта...
    DWORD ImportRVA = pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    int sect_num = -1;

    // Ищем секцию с таблицей импорта...
    sect = reinterpret_cast<IMAGE_SECTION_HEADER*>((DWORD)pe_opt_head + sizeof(IMAGE_OPTIONAL_HEADER));

    int i;
    for (i = 0; i < pe_head->NumberOfSections; i++)
    {
        if (ImportRVA < sect->VirtualAddress)
        {
            sect--;
            sect_num = i - 1;
            break;
        }
        sect++;
    }

    if (sect_num == -1)
    {
        std::cerr << "Данная программа не использует динамические библиотеки!\n";
        UnmapViewOfFile(fBeg);
        CloseHandle(hFileMap);
        return 1;
    }

    sect++;

    // Next after import table section RVA
    DWORD AfterImportSecBeg = (DWORD)fBeg + sect->PointerToRawData;
    sect--;

    // Получаем файловый указатель на раздел c  таблицей импорта.
    LPVOID ImportSecBeg = reinterpret_cast<LPVOID>((DWORD)fBeg + sect->PointerToRawData);


    // Вычисляем смещение таблицы импорта в секции импорта относительно ее начала (секции).
    LPVOID ImportTable;
    ImportTable = reinterpret_cast<LPVOID>(ImportRVA - sect->VirtualAddress);
    ImportTable = reinterpret_cast<LPVOID>((DWORD)ImportSecBeg + (DWORD)ImportTable);


    IMAGE_IMPORT_DESCRIPTOR* DLLInfo = (IMAGE_IMPORT_DESCRIPTOR*)ImportTable;
    LPVOID DLLName;
    DWORD DLLCounter = 0;

    while (DLLInfo->Name != NULL)
    {
        DLLCounter++;
        DLLName = reinterpret_cast<LPVOID>((DWORD)DLLInfo->Name - sect->VirtualAddress);
        DLLName = reinterpret_cast<LPVOID>((DWORD)ImportSecBeg + (DWORD)DLLName);

        std::cout << DLLCounter << "->" << (char*)DLLName << "\n";

        DLLInfo++;
    }
    std::cout << "Всего используется " << DLLCounter << " библиотек.\n";


    // Counting needed size in bytes for new import table.
    DWORD NewImportTableSize = sizeof(IMAGE_IMPORT_DESCRIPTOR) * (DLLCounter + 2);

    // Получаем файловый указатель на конец секции импорта.
    LPVOID pos = reinterpret_cast<LPVOID>(AfterImportSecBeg - 1);

    DWORD maxFree = 0;
    DWORD prevPtr;
    LPVOID FreePtr = NULL;

    // Ищем свободное место в секции...
    while (pos >= ImportSecBeg)
    {
        if (*(BYTE*)pos == 0x00)
        {
            prevPtr = (DWORD)pos;
            while (*(BYTE*)pos == 0x00)
                pos = reinterpret_cast<LPVOID>((DWORD)pos - 1);

            if (((DWORD)prevPtr - (DWORD)pos) > maxFree)
            {
                maxFree = ((DWORD)prevPtr - (DWORD)pos);
                FreePtr = reinterpret_cast<LPVOID>((DWORD)pos + 1);
            }
        }
        pos = reinterpret_cast<LPVOID>((DWORD)pos - 1);
    }

    // Модифицируем полученный указатель на свободный блок, т.к. он может указывать на завершающий нулевой DWORD какой-либо структуры.
    FreePtr = reinterpret_cast<LPVOID>((DWORD)FreePtr + 1);
    maxFree -= 4;

    // Проверяем объем свободного места.
    if (maxFree < NewImportTableSize)
    {
        std::cerr << "Недостаточно свободного места в таблице импорта для занесения информации об дополнительной библиотеке.\n";
        UnmapViewOfFile(fBeg);
        CloseHandle(hFileMap);
        return 1;
    }
    else
    {
        std::cerr << "Достаточно свободного места для занесения дополнительной информации.\n";
    }

    std::cout << "\nНaчинаем процесс внедрения DLL...\n";

    // 1. Копируем старую таблицу импорта в новое место.
    memcpy(FreePtr, ImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR) * DLLCounter);

    // 2.1 Сохраняем строку с именем нашей DLL в старой таблице импорта (для экономии места).
    memcpy(ImportTable, dll_name.c_str(), dll_name.length());

    LPDWORD zeroPtr = reinterpret_cast<LPDWORD>((DWORD)ImportTable + dll_name.length());



    // 2.2 Сохраняем структуру IMAGE_IMPORT_BY_NAME в старой таблице импорта (так же для экономии места).
    IMAGE_IMPORT_BY_NAME myName;
    myName.Hint = 0x00;
    myName.Name[0] = 0x00;

    WORD Hint = 0;

    hackRec patch;
    patch.ZeroDword = NULL;
    patch.IAT = ImportRVA + dll_name.length() + sizeof(hackRec);
    patch.IATEnd = NULL;

    DWORD IIBN_Table;

    memcpy(zeroPtr, &patch, sizeof(patch));
    zeroPtr = reinterpret_cast<LPDWORD>((DWORD)zeroPtr + sizeof(patch));
    memcpy(zeroPtr, &Hint, sizeof(WORD));
    zeroPtr = reinterpret_cast<LPDWORD>((DWORD)zeroPtr + sizeof(WORD));
    memcpy(zeroPtr, func_name.c_str(), func_name.length() + 1);
    zeroPtr = reinterpret_cast<LPDWORD>((DWORD)zeroPtr + func_name.length() + 1);
    memcpy(zeroPtr, &myName, sizeof(IMAGE_IMPORT_BY_NAME));

    // 2.3. Заполняем структуру IMAGE_IMPORT_BY_NAME данными о нашей DLL.
    IMAGE_IMPORT_DESCRIPTOR myDLL;

    // Вычисляем указатель на нашу структуру IMAGE_IMPORT_BY_NAME: это адрес начала старой таблицы импорта + длинна строки с именем нашей DLL + нулевой DWORD.
    IIBN_Table = ImportRVA + dll_name.length() + sizeof(DWORD);

    // Указатель на таблицу Characteristics.
    myDLL.Characteristics = IIBN_Table;
    myDLL.TimeDateStamp = NULL;
    myDLL.ForwarderChain = NULL;

    // Записываем адрес строки с именем файла нашей DLL.
    myDLL.Name = ImportRVA;

    // Указатель на таблицу FirstThunk.
    myDLL.FirstThunk = IIBN_Table;

    // Записываем в новую таблицу импорта запись о нашей DLL.
    LPVOID OldFreePtr = FreePtr;
    FreePtr = reinterpret_cast<LPVOID>((DWORD)FreePtr + sizeof(IMAGE_IMPORT_DESCRIPTOR) * DLLCounter);


    memcpy(FreePtr, &myDLL, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    // Создаем "финальную" нулевую запись со всеми полями равными нулю.
    myDLL.Characteristics = NULL;
    myDLL.TimeDateStamp = NULL;
    myDLL.ForwarderChain = NULL;
    myDLL.Name = NULL;
    myDLL.FirstThunk = NULL;

    // И записываем её в конец новой таблицы импорта.
    FreePtr = reinterpret_cast<LPVOID>((DWORD)FreePtr + sizeof(IMAGE_IMPORT_DESCRIPTOR) * DLLCounter);

    memcpy(FreePtr, &myDLL, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    // 3. Устанавливаем указатель на нашу таблицу импорта. Вычисляем RVA нашей таблицы.
    DWORD NewImportTableRVA = (DWORD)OldFreePtr - (DWORD)ImportSecBeg + sect->VirtualAddress;

    // Заносим его в DataDirectory.
    pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = NewImportTableRVA;
    pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (DLLCounter + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
    pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

    pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
    pe_opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;


    std::cout << "Успешно внедрили библиотеку \'azx\'. Для обеспечения работоспособности скопируйте файл azx в директорию модифицированной программы.\n";

    UnmapViewOfFile(fBeg);
    CloseHandle(hFileMap);

    std::cout << "\nDone\n";
    return EXIT_SUCCESS;
}
// [/main]
