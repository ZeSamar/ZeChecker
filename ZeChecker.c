/*
 * ZeChecker — проверка доступности сервера по IP и «чистоты» IP-адреса.
 *
 * Windows GUI на C (Win32 API):
 *   - доступность: системный ping.exe (ICMP), при блокировке — TCP по списку портов;
 *   - «чистота» IP по 6 сервисам;
 *   - тёмная/светлая тема (Win11), настройки с API-ключом.
 *
 * Сборка (MinGW-w64):
 *     windres app.rc -O coff -o app_res.o
 *     gcc -O2 -mwindows ZeChecker.c app_res.o -o ZeChecker.exe -lws2_32 -lwininet -ldwmapi -luxtheme
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <wchar.h>
#include <string.h>
#include <stdlib.h>

#define IDC_IP_EDIT   1001
#define IDC_BTN_START 1002
#define IDC_BTN_STOP  1003
#define IDC_LOG       1004
#define IDC_STATUS    1005
#define IDC_BTN_CHECK 1006
#define IDC_SETTINGS  1007

#define IDC_SET_KEY    2001
#define IDC_SET_SITE   2002
#define IDC_SET_DARK   2003
#define IDC_SET_OK     2004
#define IDC_SET_CANCEL 2005

#define IDI_APP 101

#define DWMWA_USE_IMMERSIVE_DARK_MODE  20
#define DWMWA_WINDOW_CORNER_PREFERENCE 33
#define DWMWCP_ROUND 2

#define WM_APP_LOG        (WM_APP + 1)
#define WM_APP_DONE       (WM_APP + 2)
#define WM_APP_CHECK_DONE (WM_APP + 3)

static HWND  g_main     = NULL;
static HWND  g_editIp   = NULL;
static HWND  g_btnStart = NULL;
static HWND  g_btnStop  = NULL;
static HWND  g_btnCheck = NULL;
static HWND  g_btnSettings = NULL;
static HWND  g_settingsHwnd = NULL;
static HWND  g_setKeyEdit = NULL;
static HWND  g_setDark   = NULL;
static HWND  g_log      = NULL;
static HWND  g_status   = NULL;
static HFONT g_fontUi   = NULL;
static HFONT g_fontMono = NULL;
static HBRUSH g_brushBg = NULL;
static COLORREF g_colorText = RGB(0, 0, 0);
static int   g_dark = 0;
static HINSTANCE g_hInstance = NULL;

static volatile LONG g_stop    = 0;
static volatile LONG g_running = 0;
static HANDLE g_hThread = NULL;

static volatile LONG g_checkRunning = 0;
static HANDLE g_checkThread = NULL;

static volatile LONG g_total = 0;
static volatile LONG g_ok    = 0;
static volatile LONG g_fail  = 0;

static ULONG   g_ip = INADDR_NONE;
static wchar_t g_ipStr[64] = L"";
static wchar_t g_apiKey[256] = L"";
static int     g_fraudScore = 0;
static int     g_flagIqs    = 0;

static void LogLine(const wchar_t* text)
{
    LRESULT idx = SendMessageW(g_log, LB_ADDSTRING, 0, (LPARAM)text);
    if (idx != LB_ERR)
        SendMessageW(g_log, LB_SETCURSEL, (WPARAM)idx, 0);
}

static void UpdateStatus(void)
{
    wchar_t buf[256];
    wsprintfW(buf, L"Проверок: %lu    Доступен: %lu    Потерян: %lu",
              (unsigned long)g_total, (unsigned long)g_ok, (unsigned long)g_fail);
    SetWindowTextW(g_status, buf);
}

static void PostLog(const wchar_t* text)
{
    size_t   len  = (wcslen(text) + 1) * sizeof(wchar_t);
    wchar_t* heap = (wchar_t*)malloc(len);
    if (heap)
    {
        memcpy(heap, text, len);
        PostMessageW(g_main, WM_APP_LOG, (WPARAM)heap, 0);
    }
}

static void ExtractField(const char* json, const char* key, wchar_t* out, size_t outChars)
{
    /* key = "имя поля" в кавычках (без двоеточия); устойчиво к пробелам после ':' */
    const char* p = strstr(json, key);
    if (!p) { out[0] = 0; return; }
    p += strlen(key);
    while (*p && *p != '"') p++;
    if (*p == '"') p++;
    size_t i = 0;
    while (i + 1 < outChars && *p && *p != '"')
        out[i++] = (wchar_t)(unsigned char)*p++;
    out[i] = 0;
}

static int HasToken(const char* json, const char* key, const char* token)
{
    /* ищет token в пределах 16 байт после "key" (для true/false и "yes"/"no") */
    const char* p = strstr(json, key);
    if (!p) return 0;
    p += strlen(key);
    size_t tl = strlen(token);
    for (int i = 0; i < 16 && p[i]; i++)
        if (strncmp(p + i, token, tl) == 0) return 1;
    return 0;
}

static int IsElevated(void)
{
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION te;
        DWORD sz = 0;
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &sz))
            elevated = te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return elevated;
}

static void LoadApiKey(void)
{
    HANDLE h = CreateFileW(L"zechecker.ini", GENERIC_READ, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD read = 0;
    if (ReadFile(h, g_apiKey, (DWORD)sizeof(g_apiKey) - 2, &read, NULL))
        g_apiKey[read / 2] = 0;
    CloseHandle(h);
}

static void SaveApiKey(void)
{
    HANDLE h = CreateFileW(L"zechecker.ini", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        PostLog(L"Ошибка: не удалось сохранить ключ.");
        return;
    }
    DWORD bytes   = (DWORD)(wcslen(g_apiKey) * sizeof(wchar_t));
    DWORD written = 0;
    WriteFile(h, g_apiKey, bytes, &written, NULL);
    CloseHandle(h);
    PostLog(L"API-ключ сохранён.");
}

static void LoadTheme(void)
{
    HANDLE h = CreateFileW(L"zechecker.cfg", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    char c = 0; DWORD read = 0;
    if (ReadFile(h, &c, 1, &read, NULL) && read == 1) g_dark = (c == '1');
    CloseHandle(h);
}

static void SaveTheme(void)
{
    HANDLE h = CreateFileW(L"zechecker.cfg", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    char c = g_dark ? '1' : '0';
    DWORD written = 0;
    WriteFile(h, &c, 1, &written, NULL);
    CloseHandle(h);
}

static COLORREF ThemeBg(void)
{
    return g_dark ? RGB(0x20, 0x20, 0x20) : RGB(0xF3, 0xF3, 0xF3);
}

static void ApplyTheme(void)
{
    BOOL dark = g_dark;
    DwmSetWindowAttribute(g_main, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    DWORD corner = DWMWCP_ROUND;
    DwmSetWindowAttribute(g_main, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));

    LPCWSTR th = g_dark ? L"DarkMode_Explorer" : L"Explorer";
    SetWindowTheme(g_editIp,   th, NULL);
    SetWindowTheme(g_log,      th, NULL);
    SetWindowTheme(g_btnStart, th, NULL);
    SetWindowTheme(g_btnStop,  th, NULL);
    SetWindowTheme(g_btnCheck, th, NULL);
    SetWindowTheme(g_btnSettings, th, NULL);

    if (g_brushBg) DeleteObject(g_brushBg);
    g_brushBg   = CreateSolidBrush(ThemeBg());
    g_colorText = g_dark ? RGB(0xFF, 0xFF, 0xFF) : RGB(0, 0, 0);

    InvalidateRect(g_main, NULL, TRUE);
}

static LRESULT OnCtlColor(HDC hdc)
{
    SetTextColor(hdc, g_colorText);
    SetBkColor(hdc, ThemeBg());
    return (LRESULT)g_brushBg;
}

static void OpenSettings(void)
{
    if (g_settingsHwnd) { SetForegroundWindow(g_settingsHwnd); return; }
    g_settingsHwnd = CreateWindowExW(0, L"ServerCheckSettings", L"Настройки",
                                     WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                                     CW_USEDEFAULT, CW_USEDEFAULT, 500, 340,
                                     g_main, NULL, g_hInstance, NULL);
    if (!g_settingsHwnd) return;
    EnableWindow(g_main, FALSE);
    ShowWindow(g_settingsHwnd, SW_SHOW);
    UpdateWindow(g_settingsHwnd);
    SetForegroundWindow(g_settingsHwnd);
}

static LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        HFONT f = CreateFontW(-15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                              DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        CreateWindowExW(0, L"STATIC", L"API-ключ ipqualityscore.com:",
                        WS_CHILD | WS_VISIBLE, 16, 16, 300, 20, hwnd, NULL, NULL, NULL);
        g_setKeyEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD,
                                       16, 40, 452, 26, hwnd, (HMENU)(INT_PTR)IDC_SET_KEY, NULL, NULL);
        CreateWindowExW(0, L"STATIC", L"Ключ бесплатный: ipqualityscore.com → Dashboard → API Keys.",
                        WS_CHILD | WS_VISIBLE, 16, 78, 452, 20, hwnd, NULL, NULL, NULL);
        g_setDark = CreateWindowExW(0, L"BUTTON", L"Тёмная тема",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                    16, 112, 200, 24, hwnd, (HMENU)(INT_PTR)IDC_SET_DARK, NULL, NULL);
        HWND btnOk = CreateWindowExW(0, L"BUTTON", L"Сохранить",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                     270, 288, 100, 32, hwnd, (HMENU)(INT_PTR)IDC_SET_OK, NULL, NULL);
        HWND btnCancel = CreateWindowExW(0, L"BUTTON", L"Отмена",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                         382, 288, 100, 32, hwnd, (HMENU)(INT_PTR)IDC_SET_CANCEL, NULL, NULL);

        if (f)
        {
            SendMessageW(g_setKeyEdit, WM_SETFONT, (WPARAM)f, TRUE);
            SendMessageW(g_setDark, WM_SETFONT, (WPARAM)f, TRUE);
            SendMessageW(btnOk, WM_SETFONT, (WPARAM)f, TRUE);
            SendMessageW(btnCancel, WM_SETFONT, (WPARAM)f, TRUE);
        }

        SetWindowTextW(g_setKeyEdit, g_apiKey);
        SendMessageW(g_setDark, BM_SETCHECK, g_dark ? BST_CHECKED : BST_UNCHECKED, 0);

        LPCWSTR th = g_dark ? L"DarkMode_Explorer" : L"Explorer";
        SetWindowTheme(g_setKeyEdit, th, NULL);
        SetWindowTheme(g_setDark, th, NULL);
        SetWindowTheme(btnOk, th, NULL);
        SetWindowTheme(btnCancel, th, NULL);

        BOOL dark = g_dark;
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
        DWORD corner = DWMWCP_ROUND;
        DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_SET_OK:
            GetWindowTextW(g_setKeyEdit, g_apiKey, 256);
            g_dark = (SendMessageW(g_setDark, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SaveApiKey();
            SaveTheme();
            ApplyTheme();
            PostLog(L"Настройки сохранены.");
            DestroyWindow(hwnd);
            return 0;
        case IDC_SET_CANCEL:
            DestroyWindow(hwnd);
            return 0;
        }
        return 0;

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
        return OnCtlColor((HDC)wParam);

    case WM_ERASEBKGND:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect((HDC)wParam, &rc, g_brushBg);
        return 1;
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        g_settingsHwnd = NULL;
        EnableWindow(g_main, TRUE);
        SetForegroundWindow(g_main);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static wchar_t* FindSubW(wchar_t* hay, const wchar_t* needle)
{
    for (wchar_t* p = hay; *p; p++)
    {
        wchar_t* a = p;
        const wchar_t* b = needle;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return p;
    }
    return NULL;
}

/* Запускает системный ping.exe и возвращает 1, если получен ответ.
   outRtt — время ответа в мс (0, если не удалось разобрать). */
static int RunPing(const wchar_t* ip, ULONG* outRtt)
{
    *outRtt = 0;

    wchar_t sysdir[MAX_PATH], cmd[512];
    if (GetSystemDirectoryW(sysdir, MAX_PATH) == 0) wcscpy(sysdir, L"C:\\Windows\\System32");
    wsprintfW(cmd, L"\"%s\\ping.exe\" -n 1 -w 1000 %s", sysdir, ip);

    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return 0;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    int success = 0;
    if (CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        CloseHandle(hWrite);
        hWrite = NULL;

        char raw[4096];
        DWORD total = 0, read = 0;
        while (total + 1 < sizeof(raw) &&
               ReadFile(hRead, raw + total, (DWORD)(sizeof(raw) - 1 - total), &read, NULL) && read > 0)
            total += read;
        raw[total] = 0;

        WaitForSingleObject(pi.hProcess, 3000);
        DWORD code = 1;
        if (!GetExitCodeProcess(pi.hProcess, &code) || code == STILL_ACTIVE)
        {
            TerminateProcess(pi.hProcess, 1);
            code = 1;
        }
        success = (code == 0);

        wchar_t wide[4096];
        int wn = MultiByteToWideChar(CP_OEMCP, 0, raw, -1, wide, 4096);
        if (wn <= 0) wide[0] = 0;
        for (wchar_t* q = wide; *q; q++)
            if (*q == L'\r' || *q == L'\n') *q = L' ';

        if (wn > 0)
        {
            wchar_t* p = FindSubW(wide, L"time=");
            if (p) p += 5;
            else { p = FindSubW(wide, L"время="); if (p) p += 6; }
            if (p)
            {
                ULONG v = 0;
                while (*p == L' ' || *p == L'=') p++;
                while (*p >= L'0' && *p <= L'9') { v = v * 10 + (ULONG)(*p - L'0'); p++; }
                *outRtt = v;
            }
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    if (hWrite) CloseHandle(hWrite);
    CloseHandle(hRead);
    return success;
}

/* TCP-проверка доступности порта (работает без прав администратора) */
static int TcpCheck(const wchar_t* ip, int port)
{
    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    if (InetPtonW(AF_INET, ip, &addr.sin_addr) != 1) return 0;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;

    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);

    int ok = 0;
    if (connect(s, (SOCKADDR*)&addr, sizeof(addr)) == 0) ok = 1;
    else if (WSAGetLastError() == WSAEWOULDBLOCK)
    {
        fd_set wf;
        FD_ZERO(&wf);
        FD_SET(s, &wf);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select(0, NULL, &wf, NULL, &tv) > 0) ok = 1;
    }
    closesocket(s);
    return ok;
}

static DWORD WINAPI PingThreadProc(LPVOID param)
{
    (void)param;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    while (!g_stop)
    {
        ULONG rtt = 0;
        int method = 0;
        int openPort = 0;

        if (RunPing(g_ipStr, &rtt)) method = 1;
        else
        {
            static const int ports[] = { 22, 80, 443, 8080, 3389, 21, 3306, 25, 110, 143, 53, 8443 };
            int n = (int)(sizeof(ports) / sizeof(ports[0]));
            for (int i = 0; i < n; i++)
            {
                if (TcpCheck(g_ipStr, ports[i])) { method = 2; openPort = ports[i]; break; }
            }
        }

        if (g_stop) break;

        SYSTEMTIME st;
        GetLocalTime(&st);

        wchar_t line[512];
        if (method == 1)
        {
            wsprintfW(line, L"%02u:%02u:%02u  [ОК]  %s  —  ответ за %lu мс",
                      st.wHour, st.wMinute, st.wSecond, g_ipStr, (unsigned long)rtt);
            InterlockedIncrement(&g_ok);
        }
        else if (method == 2)
        {
            wsprintfW(line, L"%02u:%02u:%02u  [ОК]  %s  —  доступен (TCP:%d)",
                      st.wHour, st.wMinute, st.wSecond, g_ipStr, openPort);
            InterlockedIncrement(&g_ok);
        }
        else
        {
            wsprintfW(line, L"%02u:%02u:%02u  [НЕТ ОТВЕТА]  %s",
                      st.wHour, st.wMinute, st.wSecond, g_ipStr);
            InterlockedIncrement(&g_fail);
        }
        InterlockedIncrement(&g_total);

        size_t   len  = (wcslen(line) + 1) * sizeof(wchar_t);
        wchar_t* heap = (wchar_t*)malloc(len);
        if (heap)
        {
            memcpy(heap, line, len);
            PostMessageW(g_main, WM_APP_LOG, (WPARAM)heap, 0);
        }

        /* интервал между проверками ~1 с, с отзывчивостью на "Стоп" */
        for (int i = 0; i < 5 && !g_stop; i++)
            Sleep(200);
    }

    WSACleanup();
    PostMessageW(g_main, WM_APP_DONE, 0, 0);
    return 0;
}

static int HttpGet(const wchar_t* url, char* buf, int bufSize)
{
    HINTERNET hNet = InternetOpenW(L"ZeChecker/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hNet) return -1;

    HINTERNET hUrl = InternetOpenUrlW(hNet, url, NULL, 0,
                                      INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, 0);
    if (!hUrl) { InternetCloseHandle(hNet); return -1; }

    DWORD total = 0, read = 0;
    while (total + 1 < (DWORD)bufSize &&
           InternetReadFile(hUrl, buf + total, (DWORD)(bufSize - 1 - total), &read) && read > 0)
        total += read;
    buf[total] = 0;

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hNet);
    return (int)total;
}

static DWORD WINAPI CheckThreadProc(LPVOID param)
{
    wchar_t* ip = (wchar_t*)param;

    char    buf[8192];
    wchar_t url[512], line[512], cc[8], s2[128];
    int proxy_api = 0, hosting_api = 0, proxy_pc = 0;

    PostLog(L"=== Проверка чистоты IP ===");
    wsprintfW(line, L"IP: %s", ip);
    PostLog(line);

    /* 1) ip-api.com */
    wsprintfW(url, L"http://ip-api.com/json/%s?fields=status,countryCode,isp,proxy,hosting", ip);
    if (HttpGet(url, buf, sizeof(buf)) > 0 && !strstr(buf, "\"status\":\"fail\""))
    {
        ExtractField(buf, "\"countryCode\"", cc, 8);
        ExtractField(buf, "\"isp\"", s2, 128);
        proxy_api   = HasToken(buf, "\"proxy\"", "true");
        hosting_api = HasToken(buf, "\"hosting\"", "true");
        wsprintfW(line, L"ip-api.com:    %s | прокси=%s | хостинг=%s | %s",
                  cc, proxy_api ? L"Да" : L"Нет", hosting_api ? L"Да" : L"Нет", s2);
    }
    else wsprintfW(line, L"ip-api.com:    ошибка запроса");
    PostLog(line);

    /* 2) proxycheck.io */
    wsprintfW(url, L"https://proxycheck.io/v2/%s?vpn=1&asn=1&risk=1", ip);
    if (HttpGet(url, buf, sizeof(buf)) > 0)
    {
        ExtractField(buf, "\"isocode\"", cc, 8);
        proxy_pc = HasToken(buf, "\"proxy\"", "yes");
        ExtractField(buf, "\"type\"", s2, 128);
        wsprintfW(line, L"proxycheck.io: %s | прокси=%s | тип=%s", cc, proxy_pc ? L"Да" : L"Нет", s2);
    }
    else wsprintfW(line, L"proxycheck.io: ошибка запроса");
    PostLog(line);

    /* 3) ipwho.is */
    wsprintfW(url, L"https://ipwho.is/%s", ip);
    if (HttpGet(url, buf, sizeof(buf)) > 0)
    {
        ExtractField(buf, "\"country_code\"", cc, 8);
        ExtractField(buf, "\"org\"", s2, 128);
        wsprintfW(line, L"ipwho.is:      %s | %s", cc, s2);
    }
    else wsprintfW(line, L"ipwho.is:      ошибка запроса");
    PostLog(line);

    /* 4) ipinfo.io */
    wsprintfW(url, L"https://ipinfo.io/%s/json", ip);
    if (HttpGet(url, buf, sizeof(buf)) > 0)
    {
        ExtractField(buf, "\"country\"", cc, 8);
        ExtractField(buf, "\"org\"", s2, 128);
        wsprintfW(line, L"ipinfo.io:     %s | %s", cc, s2);
    }
    else wsprintfW(line, L"ipinfo.io:     ошибка запроса");
    PostLog(line);

    /* 5) ip2c.org */
    wsprintfW(url, L"https://ip2c.org/%s", ip);
    if (HttpGet(url, buf, sizeof(buf)) > 0)
    {
        char* semi = strchr(buf, ';');
        if (semi && semi[1] && semi[2])
        {
            cc[0] = (wchar_t)(unsigned char)semi[1];
            cc[1] = (wchar_t)(unsigned char)semi[2];
            cc[2] = 0;
        }
        else wcscpy(cc, L"??");
        wsprintfW(line, L"ip2c.org:      %s", cc);
    }
    else wsprintfW(line, L"ip2c.org:      ошибка запроса");
    PostLog(line);

    /* 6) ipqualityscore.com */
    g_fraudScore = 0;
    g_flagIqs    = 0;
    if (g_apiKey[0])
    {
        wsprintfW(url, L"https://www.ipqualityscore.com/api/json/ip/%s/%s", g_apiKey, ip);
        if (HttpGet(url, buf, sizeof(buf)) > 0 && strstr(buf, "\"success\":true"))
        {
            ExtractField(buf, "\"country_code\"", cc, 8);
            ExtractField(buf, "\"ISP\"", s2, 128);
            g_flagIqs = HasToken(buf, "\"proxy\"", "true") || HasToken(buf, "\"vpn\"", "true") || HasToken(buf, "\"tor\"", "true");
            const char* fs = strstr(buf, "\"fraud_score\":");
            g_fraudScore = fs ? atoi(fs + 14) : 0;
            wsprintfW(line, L"ipqualityscore: %s | fraud=%d | прокси=%s | %s",
                      cc, g_fraudScore, g_flagIqs ? L"Да" : L"Нет", s2);
        }
        else wsprintfW(line, L"ipqualityscore: ошибка запроса");
        PostLog(line);
    }
    else
    {
        PostLog(L"ipqualityscore: нет API-ключа (введите и нажмите «Сохранить»)");
    }

    /* вердикт */
    if (proxy_api || hosting_api || proxy_pc || g_flagIqs || g_fraudScore >= 75)
        PostLog(L"Вердикт: ПОДОЗРИТЕЛЬНЫЙ (прокси/датацентр/VPN)");
    else
        PostLog(L"Вердикт: вероятно чистый (жилой) IP");

    free(ip);
    PostMessageW(g_main, WM_APP_CHECK_DONE, 0, 0);
    return 0;
}

static void StartCheckIp(void)
{
    if (g_checkRunning) return;

    wchar_t wip[64];
    GetWindowTextW(g_editIp, wip, 64);

    wchar_t* p = wip;
    while (*p == L' ' || *p == L'\t') p++;
    size_t l = wcslen(p);
    while (l > 0 && (p[l - 1] == L' ' || p[l - 1] == L'\t')) p[--l] = 0;

    if (l == 0)
    {
        MessageBoxW(g_main, L"Введите IP-адрес.", L"Ошибка", MB_OK | MB_ICONWARNING);
        return;
    }

    IN_ADDR a;
    if (InetPtonW(AF_INET, p, &a) != 1)
    {
        MessageBoxW(g_main, L"Некорректный IP-адрес.\nОжидается формат: x.x.x.x", L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    wchar_t* ipcopy = (wchar_t*)malloc((wcslen(p) + 1) * sizeof(wchar_t));
    if (!ipcopy) return;
    wcscpy(ipcopy, p);

    g_checkThread = CreateThread(NULL, 0, CheckThreadProc, ipcopy, 0, NULL);
    if (!g_checkThread)
    {
        free(ipcopy);
        MessageBoxW(g_main, L"Не удалось создать поток.", L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    g_checkRunning = 1;
    EnableWindow(g_btnCheck, FALSE);
}

static void StartCheck(void)
{
    if (g_running) return;

    wchar_t wip[64];
    GetWindowTextW(g_editIp, wip, 64);

    wchar_t* p = wip;
    while (*p == L' ' || *p == L'\t') p++;
    size_t l = wcslen(p);
    while (l > 0 && (p[l - 1] == L' ' || p[l - 1] == L'\t')) p[--l] = 0;

    if (l == 0)
    {
        MessageBoxW(g_main, L"Введите IP-адрес сервера.", L"Ошибка", MB_OK | MB_ICONWARNING);
        return;
    }

    IN_ADDR a;
    if (InetPtonW(AF_INET, p, &a) != 1)
    {
        MessageBoxW(g_main, L"Некорректный IP-адрес.\nОжидается формат: x.x.x.x",
                    L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    g_ip = a.S_un.S_addr;
    wcscpy(g_ipStr, p);

    SendMessageW(g_log, LB_RESETCONTENT, 0, 0);
    g_total = g_ok = g_fail = 0;
    UpdateStatus();

    wchar_t msg[256];
    wsprintfW(msg, L"Начата проверка: %s", g_ipStr);
    LogLine(msg);

    g_stop    = 0;
    g_hThread = CreateThread(NULL, 0, PingThreadProc, NULL, 0, NULL);
    if (!g_hThread)
    {
        MessageBoxW(g_main, L"Не удалось создать поток.", L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    g_running = 1;
    EnableWindow(g_btnStart, FALSE);
    EnableWindow(g_btnStop, TRUE);
    SetWindowTextW(g_btnStop, L"Стоп");
}

static void StopCheck(void)
{
    if (!g_running) return;
    InterlockedExchange(&g_stop, 1);
    EnableWindow(g_btnStop, FALSE);
    SetWindowTextW(g_btnStop, L"Останавливается...");
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        g_fontUi = CreateFontW(-15, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_fontMono = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Consolas");

        CreateWindowExW(0, L"STATIC", L"IP-адрес сервера:",
                        WS_CHILD | WS_VISIBLE,
                        12, 16, 130, 22, hwnd, NULL, NULL, NULL);

        g_editIp = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                   145, 12, 230, 24, hwnd, (HMENU)(INT_PTR)IDC_IP_EDIT, NULL, NULL);

        g_btnStart = CreateWindowExW(0, L"BUTTON", L"Старт",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                     388, 10, 110, 28, hwnd, (HMENU)(INT_PTR)IDC_BTN_START, NULL, NULL);

        g_btnStop = CreateWindowExW(0, L"BUTTON", L"Стоп",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                    388, 44, 110, 28, hwnd, (HMENU)(INT_PTR)IDC_BTN_STOP, NULL, NULL);

        g_btnCheck = CreateWindowExW(0, L"BUTTON", L"Чистота IP",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                     388, 78, 110, 28, hwnd, (HMENU)(INT_PTR)IDC_BTN_CHECK, NULL, NULL);

        g_btnSettings = CreateWindowExW(0, L"BUTTON", L"Настройки",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                        388, 112, 110, 28, hwnd, (HMENU)(INT_PTR)IDC_SETTINGS, NULL, NULL);

        g_status = CreateWindowExW(0, L"STATIC", L"",
                                   WS_CHILD | WS_VISIBLE | SS_LEFT,
                                   12, 48, 360, 20, hwnd, (HMENU)(INT_PTR)IDC_STATUS, NULL, NULL);

        g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                                WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_NOSEL,
                                12, 150, 486, 310, hwnd, (HMENU)(INT_PTR)IDC_LOG, NULL, NULL);

        if (g_fontMono)
        {
            SendMessageW(g_log,         WM_SETFONT, (WPARAM)g_fontMono, TRUE);
            SendMessageW(g_status,      WM_SETFONT, (WPARAM)g_fontUi, TRUE);
            SendMessageW(g_editIp,      WM_SETFONT, (WPARAM)g_fontUi, TRUE);
            SendMessageW(g_btnStart,    WM_SETFONT, (WPARAM)g_fontUi, TRUE);
            SendMessageW(g_btnStop,     WM_SETFONT, (WPARAM)g_fontUi, TRUE);
            SendMessageW(g_btnCheck,    WM_SETFONT, (WPARAM)g_fontUi, TRUE);
            SendMessageW(g_btnSettings, WM_SETFONT, (WPARAM)g_fontUi, TRUE);
        }

        EnableWindow(g_btnStop, FALSE);
        UpdateStatus();
        LoadApiKey();
        LoadTheme();
        ApplyTheme();
        SetFocus(g_editIp);
        return 0;
    }

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_BTN_START: StartCheck();   return 0;
        case IDC_BTN_STOP:  StopCheck();    return 0;
        case IDC_BTN_CHECK: StartCheckIp(); return 0;
        case IDC_SETTINGS:  OpenSettings(); return 0;
        }
        return 0;
    }

    case WM_APP_LOG:
    {
        wchar_t* s = (wchar_t*)wParam;
        if (s)
        {
            LogLine(s);
            free(s);
        }
        UpdateStatus();
        return 0;
    }

    case WM_APP_DONE:
    {
        if (g_hThread)
        {
            CloseHandle(g_hThread);
            g_hThread = NULL;
        }
        g_running = 0;
        EnableWindow(g_btnStart, TRUE);
        EnableWindow(g_btnStop, FALSE);
        SetWindowTextW(g_btnStop, L"Стоп");
        LogLine(L"Проверка остановлена.");
        UpdateStatus();
        return 0;
    }

    case WM_APP_CHECK_DONE:
    {
        if (g_checkThread)
        {
            CloseHandle(g_checkThread);
            g_checkThread = NULL;
        }
        g_checkRunning = 0;
        EnableWindow(g_btnCheck, TRUE);
        return 0;
    }

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
        return OnCtlColor((HDC)wParam);

    case WM_ERASEBKGND:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect((HDC)wParam, &rc, g_brushBg);
        return 1;
    }

    case WM_CLOSE:
        if (g_running)
        {
            InterlockedExchange(&g_stop, 1);
            WaitForSingleObject(g_hThread, 1500);
        }
        if (g_checkRunning)
        {
            WaitForSingleObject(g_checkThread, 1500);
        }
        if (g_settingsHwnd) DestroyWindow(g_settingsHwnd);
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        if (g_fontUi)   DeleteObject(g_fontUi);
        if (g_fontMono) DeleteObject(g_fontMono);
        if (g_brushBg)  DeleteObject(g_brushBg);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrev;
    (void)lpCmdLine;

    g_hInstance = hInstance;

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"ZeCheckerWnd";
    wc.hIcon         = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_APP));
    wc.hIconSm       = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_APP));

    if (!RegisterClassExW(&wc))
        return 1;

    WNDCLASSEXW wcs;
    ZeroMemory(&wcs, sizeof(wcs));
    wcs.cbSize        = sizeof(wcs);
    wcs.lpfnWndProc   = SettingsWndProc;
    wcs.hInstance     = hInstance;
    wcs.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    wcs.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wcs.lpszClassName = L"ZeCheckerSettings";
    wcs.hIcon         = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_APP));
    wcs.hIconSm       = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_APP));
    RegisterClassExW(&wcs);

    int w = 520, h = 500;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    g_main = CreateWindowExW(0, wc.lpszClassName,
                             L"ZeChecker — проверка доступности сервера",
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                             x, y, w, h, NULL, NULL, hInstance, NULL);
    if (!g_main)
        return 1;

    ShowWindow(g_main, nCmdShow);
    UpdateWindow(g_main);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
