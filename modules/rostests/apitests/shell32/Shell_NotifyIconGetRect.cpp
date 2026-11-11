/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     Tests for Shell_NotifyIconGetRect
 */

#include <apitest.h>
#include <windows.h>
#include <shellapi.h>

typedef HRESULT (WINAPI *SHELL_NOTIFYICONGETRECT)(const NOTIFYICONIDENTIFIER*, RECT*);

static const RECT g_SentinelRect = { 0x11111111, 0x22222222, 0x33333333, 0x44444444 };

static void
CheckRect(const RECT& Rect, LONG Left, LONG Top, LONG Right, LONG Bottom)
{
    ok(Rect.left == Left && Rect.top == Top && Rect.right == Right && Rect.bottom == Bottom,
       "rect is (%ld,%ld)-(%ld,%ld), expected (%ld,%ld)-(%ld,%ld)\n",
       Rect.left, Rect.top, Rect.right, Rect.bottom, Left, Top, Right, Bottom);
}

static void
CheckQueryResult(SHELL_NOTIFYICONGETRECT GetRect, const NOTIFYICONIDENTIFIER& Identifier,
                 HRESULT Expected)
{
    RECT Rect = g_SentinelRect;
    HRESULT Result = GetRect(&Identifier, &Rect);
    ok_hex(Result, Expected);
    CheckRect(Rect, 0, 0, 0, 0);
}

/* The shell handles a new icon and a click on its own time */
static HRESULT
QueryUntil(SHELL_NOTIFYICONGETRECT GetRect, const NOTIFYICONIDENTIFIER& Identifier, HRESULT First, HRESULT Second, RECT *Rect)
{
    HRESULT Result = E_FAIL;

    for (int Try = 0; Try < 30; Try++)
    {
        MSG Msg;

        while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&Msg);
        *Rect = g_SentinelRect;
        Result = GetRect(&Identifier, Rect);
        if (Result == First || Result == Second)
            break;
        Sleep(100);
    }
    return Result;
}

static void
Click(const RECT& Rect)
{
    INPUT Input[3] = { { 0 } };

    Input[0].type = Input[1].type = Input[2].type = INPUT_MOUSE;
    Input[0].mi.dx = (Rect.left + Rect.right) / 2 * 65535 / (GetSystemMetrics(SM_CXSCREEN) - 1);
    Input[0].mi.dy = (Rect.top + Rect.bottom) / 2 * 65535 / (GetSystemMetrics(SM_CYSCREEN) - 1);
    Input[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
    Input[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
    Input[2].mi.dwFlags = MOUSEEVENTF_LEFTUP;
    ok(SendInput(3, Input, sizeof(INPUT)) == 3, "SendInput failed with %lu\n", GetLastError());
}

START_TEST(Shell_NotifyIconGetRect)
{
    HMODULE Shell32 = GetModuleHandleW(L"shell32.dll");
    SHELL_NOTIFYICONGETRECT GetRect;
    NOTIFYICONIDENTIFIER Identifier = { 0 };
    NOTIFYICONDATAW Icon = { 0 };
    RECT Rect, Button;
    HRESULT Result;
    BOOL InOverflow = FALSE;
    HWND Window;
    BOOL Added;

    GetRect = reinterpret_cast<SHELL_NOTIFYICONGETRECT>(GetProcAddress(Shell32, "Shell_NotifyIconGetRect"));
    if (!GetRect)
    {
        skip("Shell_NotifyIconGetRect is not exported\n");
        return;
    }

    Rect = g_SentinelRect;
    Result = GetRect(NULL, &Rect);
    ok_hex(Result, E_POINTER);
    CheckRect(Rect, g_SentinelRect.left, g_SentinelRect.top,
              g_SentinelRect.right, g_SentinelRect.bottom);

    Identifier.cbSize = sizeof(Identifier);
    Result = GetRect(&Identifier, NULL);
    ok_hex(Result, E_POINTER);

    Identifier.cbSize = 0;
    CheckQueryResult(GetRect, Identifier, E_INVALIDARG);
    Identifier.cbSize = sizeof(Identifier) - 1;
    CheckQueryResult(GetRect, Identifier, E_INVALIDARG);
    Identifier.cbSize = sizeof(Identifier) + 1;
    CheckQueryResult(GetRect, Identifier, E_INVALIDARG);

    Identifier.cbSize = sizeof(Identifier);
    CheckQueryResult(GetRect, Identifier, E_FAIL);

    Window = CreateWindowExW(0, L"STATIC", L"Shell_NotifyIconGetRect test", WS_OVERLAPPED,
                             0, 0, 100, 100, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(Window != NULL, "CreateWindowExW failed with %lu\n", GetLastError());
    if (!Window)
        return;

    Icon.cbSize = sizeof(Icon);
    Icon.hWnd = Window;
    Icon.uID = 42;
    Icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    Icon.uCallbackMessage = WM_APP + 1;
    Icon.hIcon = LoadIconW(NULL, MAKEINTRESOURCEW(32512));
    lstrcpyW(Icon.szTip, L"Shell_NotifyIconGetRect test");
    Added = Shell_NotifyIconW(NIM_ADD, &Icon);
    ok(Added, "NIM_ADD failed with %lu\n", GetLastError());

    if (Added)
    {
        Identifier.hWnd = Window;
        Identifier.uID = Icon.uID;
        Result = QueryUntil(GetRect, Identifier, S_OK, S_FALSE, &Rect);
        ok(Result == S_OK || Result == S_FALSE, "unexpected result 0x%08lx\n", Result);
        ok(Rect.right > Rect.left && Rect.bottom > Rect.top, "invalid rect (%ld,%ld)-(%ld,%ld)\n", Rect.left, Rect.top, Rect.right, Rect.bottom);

        /* S_FALSE comes with the rectangle of the overflow button: the new icon is in the closed overflow area */
        if (Result == S_FALSE)
        {
            Button = Rect;
            InOverflow = TRUE;
            Click(Button);
            Result = QueryUntil(GetRect, Identifier, S_OK, S_OK, &Rect);
            ok_hex(Result, S_OK);
            ok(!EqualRect(&Rect, &Button), "the open overflow area still gives the button (%ld,%ld)-(%ld,%ld)\n",
               Rect.left, Rect.top, Rect.right, Rect.bottom);
            ok(Rect.right - Rect.left >= GetSystemMetrics(SM_CXSMICON) && Rect.bottom - Rect.top >= GetSystemMetrics(SM_CYSMICON),
               "the rect (%ld,%ld)-(%ld,%ld) is smaller than the icon\n", Rect.left, Rect.top, Rect.right, Rect.bottom);

            Click(Button);
            Result = QueryUntil(GetRect, Identifier, S_FALSE, S_FALSE, &Rect);
            ok_hex(Result, S_FALSE);
            ok(EqualRect(&Rect, &Button), "the closed overflow area gives (%ld,%ld)-(%ld,%ld), not the button\n",
               Rect.left, Rect.top, Rect.right, Rect.bottom);
        }

        Identifier.uID++;
        CheckQueryResult(GetRect, Identifier, E_FAIL);
        Identifier.uID--;

        Icon.uFlags = NIF_STATE;
        Icon.dwStateMask = NIS_HIDDEN;
        Icon.dwState = NIS_HIDDEN;
        ok(Shell_NotifyIconW(NIM_MODIFY, &Icon), "hiding icon failed with %lu\n", GetLastError());
        Sleep(100);
        if (InOverflow)
        {
            /* On Windows 11 an icon with NIS_HIDDEN still gets the button of the closed overflow area */
            Rect = g_SentinelRect;
            Result = GetRect(&Identifier, &Rect);
            ok_hex(Result, S_FALSE);
            ok(EqualRect(&Rect, &Button), "the hidden icon gives (%ld,%ld)-(%ld,%ld), not the button\n", Rect.left, Rect.top, Rect.right, Rect.bottom);
        }
        else
        {
            CheckQueryResult(GetRect, Identifier, E_FAIL);
        }

        ok(Shell_NotifyIconW(NIM_DELETE, &Icon), "NIM_DELETE failed with %lu\n", GetLastError());
        CheckQueryResult(GetRect, Identifier, E_FAIL);
    }

    DestroyWindow(Window);
}
