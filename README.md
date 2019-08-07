# pe-file

Программа для жесткого внедрения DLL библиотек.
Проект разработан в среде Visual Studio 2019.

    Usage:
        pe-file.exe
            [*.exe || *.dll]  - input PE file
            [*.dll]           - will be added to the import table
            [function]        - imported function

### Примечание

После успешного внедрения, для обеспечения работоспособности, скопируйте файл библиотеки в директорию модифицированной программы.
