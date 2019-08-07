#include <tchar.h>
#include <windows.h>

// [Thread1]:
DWORD WINAPI Thread1(LPVOID lpObject)
{
    HWND hWnd = FindWindow(_T("_test_program_class_"), _T("TestProgram"));
    if (hWnd)
    {
        MessageBox(hWnd, "We are hacked!", "Oops...", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);

        HDC hDC = GetDC(hWnd);
        if (hDC)
        {
            RECT rc;
            GetClientRect(hWnd, &rc);
            const int iWindowWidth = rc.right - rc.left;
            const int iWindowHeight = rc.bottom - rc.top;

            LOGFONT lf;
            memset(&lf, 0, sizeof(LOGFONT));
            lstrcpy(lf.lfFaceName, _T("Arial"));
            lf.lfHeight = 30;
            HFONT hFont = CreateFontIndirect(&lf);

            int iOldBkMode = SetBkMode(hDC, TRANSPARENT);
            COLORREF clrOldColor = SetTextColor(hDC, RGB(255, 0, 0));
            HFONT hOldFont = (HFONT)SelectObject(hDC, hFont);

            TCHAR szText[] = _T("We are hacked!");

            SIZE size;
            GetTextExtentPoint32(hDC, szText, lstrlen(szText), &size);

            TextOut(
                hDC,
                (iWindowWidth >> 1) - (size.cx >> 1),
                (iWindowHeight >> 1) - (size.cy >> 1),
                szText,
                lstrlen(szText)
            );

            SelectObject(hDC, hOldFont);
            SetTextColor(hDC, clrOldColor);
            SetBkMode(hDC, iOldBkMode);

            ReleaseDC(hWnd, hDC);
        }
    }
    else
    {
        MessageBox(NULL, "We are hacked!", "Oops...", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
    }
    ExitThread(1337);
}
// [/Thread1]


// [DllMain]:
BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DWORD dwThreadId = 0;
        HANDLE hThread = CreateThread(NULL, 0, Thread1, NULL, 0, &dwThreadId);
        if (hThread)
        {
            CloseHandle(hThread);
        }
    }
    break;

    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
// [/DllMain]
