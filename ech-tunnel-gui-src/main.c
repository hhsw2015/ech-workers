#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Unique name for Mutex
#define SINGLE_INSTANCE_MUTEX_NAME "ECHTunnelClient_Mutex_Unique_ID"

// 图标资源 ID
#define IDI_APP_ICON 101 

// 声明 DPI 感知函数
typedef BOOL (WINAPI *SetProcessDPIAwareFunc)(void);

// 版本信息
#define APP_VERSION "1.0"
#define APP_TITLE "ECH Tunnel 客户端 v" APP_VERSION

// 缓冲区大小定义
#define MAX_URL_LEN 8192
#define MAX_SMALL_LEN 2048
#define MAX_CMD_LEN 32768

// 消息定义
#define WM_TRAYICON (WM_USER + 1)
#define WM_APPEND_LOG (WM_USER + 2) 

// 托盘菜单ID
#define ID_TRAY_ICON 9001
#define ID_TRAY_OPEN 9002
#define ID_TRAY_EXIT 9003

// 字体与绘图对象
HFONT hFontUI = NULL;    
HFONT hFontLog = NULL;   
HBRUSH hBrushLog = NULL;

// DPI 感知
int g_dpi = 96;
int g_scale = 100;

// 缩放函数
int Scale(int x) {
    return (x * g_scale) / 100;
}

// 窗口控件ID定义
#define ID_SERVER_EDIT      1001
#define ID_LISTEN_EDIT      1002
#define ID_TOKEN_EDIT       1003
#define ID_IP_EDIT          1004
#define ID_DNS_EDIT         1005
#define ID_ECH_EDIT         1006
#define ID_CONN_EDIT        1007
#define ID_CONN_UP          1008
#define ID_CONN_DOWN        1009
#define ID_START_BTN        1010
#define ID_STOP_BTN         1011
#define ID_CLEAR_LOG_BTN    1012
#define ID_LOG_EDIT         1013

// 全局变量
HWND hMainWindow;
HWND hServerEdit, hListenEdit, hTokenEdit, hIpEdit, hDnsEdit, hEchEdit;
HWND hConnEdit, hStartBtn, hStopBtn, hLogEdit;
PROCESS_INFORMATION processInfo;
HANDLE hLogPipe = NULL;
HANDLE hLogThread = NULL;
BOOL isProcessRunning = FALSE;
NOTIFYICONDATA nid;

// 配置结构体
typedef struct {
    char dns[MAX_SMALL_LEN];     
    char ech[MAX_SMALL_LEN];     
    char server[MAX_URL_LEN];    
    char ip[MAX_SMALL_LEN];      
    char listen[MAX_SMALL_LEN];  
    int connections;
    char token[MAX_URL_LEN];     
} Config;

Config currentConfig = {
    "", "", "example.com:443", "", "127.0.0.1:30000", 3, ""
};

// 函数声明
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void CreateControls(HWND hwnd);
void StartProcess();
void StopProcess();
void AppendLog(const char* text);
void AppendLogAsync(const char* text);
DWORD WINAPI LogReaderThread(LPVOID lpParam);
void SaveConfig();
void LoadConfig();
void GetControlValues();
void SetControlValues();
void InitTrayIcon(HWND hwnd);
void ShowTrayIcon();
void RemoveTrayIcon();

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)lpCmdLine;
    
    // --- 单实例检查开始 ---
    HANDLE hMutex = CreateMutex(NULL, TRUE, SINGLE_INSTANCE_MUTEX_NAME);

    // 检查互斥体是否已经存在
    if (hMutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        // 找到已运行的实例窗口
        HWND hExistingWnd = FindWindow("ECHTunnelClient", NULL); 
        if (hExistingWnd) {
            // 发送消息，让已运行的实例窗口显示
            PostMessage(hExistingWnd, WM_TRAYICON, ID_TRAY_ICON, WM_LBUTTONUP);
        }
        // 关闭互斥体句柄并退出新实例
        CloseHandle(hMutex);
        return 0; 
    }
    // --- 单实例检查结束 ---
    
    HMODULE hUser32 = LoadLibrary("user32.dll");
    if (hUser32) {
        SetProcessDPIAwareFunc setDPIAware = (SetProcessDPIAwareFunc)(void*)GetProcAddress(hUser32, "SetProcessDPIAware");
        if (setDPIAware) setDPIAware();
        FreeLibrary(hUser32);
    }
    
    HDC hdc = GetDC(NULL);
    g_dpi = GetDeviceCaps(hdc, LOGPIXELSX);
    g_scale = (g_dpi * 100) / 96;
    ReleaseDC(NULL, hdc);
    
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    hFontUI = CreateFont(Scale(19), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, 
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, 
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Microsoft YaHei UI");

    hFontLog = CreateFont(Scale(16), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, 
        ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, 
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

    hBrushLog = CreateSolidBrush(RGB(255, 255, 255));

    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "ECHTunnelClient"; // Class Name used by FindWindow
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1); 
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APP_ICON));
    if (!wc.hIcon) wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClass(&wc)) return 1;

    int winWidth = Scale(900);
    int winHeight = Scale(720);
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    DWORD winStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;

    hMainWindow = CreateWindowEx(
        0, "ECHTunnelClient", APP_TITLE, 
        winStyle,
        (screenW - winWidth) / 2, (screenH - winHeight) / 2, 
        winWidth, winHeight,
        NULL, NULL, hInstance, NULL
    );

    if (!hMainWindow) return 1;

    InitTrayIcon(hMainWindow);

    ShowWindow(hMainWindow, nCmdShow);
    UpdateWindow(hMainWindow);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_TAB) {
            IsDialogMessage(hMainWindow, &msg);
        } else {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    
    // (Optional) Release mutex ownership when the first instance exits
    CloseHandle(hMutex); 

    return (int)msg.wParam;
}

// ... (Rest of the functions remain the same) ...

void InitTrayIcon(HWND hwnd) {
    memset(&nid, 0, sizeof(NOTIFYICONDATA));
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = ID_TRAY_ICON;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_APP_ICON));
    if (!nid.hIcon) nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    strcpy(nid.szTip, APP_TITLE);
}

void ShowTrayIcon() {
    Shell_NotifyIcon(NIM_ADD, &nid);
}

void RemoveTrayIcon() {
    Shell_NotifyIcon(NIM_DELETE, &nid);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            CreateControls(hwnd);
            LoadConfig();
            SetControlValues();
            break;

        case WM_SYSCOMMAND:
            if ((wParam & 0xFFF0) == SC_MINIMIZE) {
                ShowWindow(hwnd, SW_HIDE); 
                ShowTrayIcon();            
                return 0;                  
            }
            return DefWindowProc(hwnd, uMsg, wParam, lParam);

        case WM_TRAYICON:
            if (lParam == WM_LBUTTONUP) {
                // 托盘点击或第二个实例发送的消息会触发此逻辑
                ShowWindow(hwnd, SW_RESTORE);
                SetForegroundWindow(hwnd);
                RemoveTrayIcon(); // 恢复后移除托盘图标
            } 
            else if (lParam == WM_RBUTTONUP) {
                POINT pt;
                GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                if (hMenu) {
                    AppendMenu(hMenu, MF_STRING, ID_TRAY_OPEN, "打开界面");
                    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
                    AppendMenu(hMenu, MF_STRING, ID_TRAY_EXIT, "退出程序");
                    SetForegroundWindow(hwnd); 
                    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
                    DestroyMenu(hMenu);
                }
            }
            break;

        case WM_APPEND_LOG: {
            char* logText = (char*)lParam;
            if (logText) {
                AppendLog(logText);
                free(logText);
            }
            break;
        }

        case WM_CTLCOLORSTATIC: {
            HDC hdcStatic = (HDC)wParam;
            HWND hCtrl = (HWND)lParam;
            int ctrlId = GetDlgCtrlID(hCtrl);
            if (ctrlId == ID_LOG_EDIT) {
                SetBkColor(hdcStatic, RGB(255, 255, 255)); 
                SetBkMode(hdcStatic, OPAQUE);              
                return (LRESULT)hBrushLog;                 
            }
            SetBkMode(hdcStatic, TRANSPARENT);             
            return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_TRAY_OPEN:
                    ShowWindow(hwnd, SW_RESTORE);
                    SetForegroundWindow(hwnd);
                    RemoveTrayIcon();
                    break;
                
                case ID_TRAY_EXIT:
                    SendMessage(hwnd, WM_CLOSE, 0, 0);
                    break;

                case ID_START_BTN:
                    if (!isProcessRunning) {
                        GetControlValues();
                        if (strlen(currentConfig.server) == 0) {
                            MessageBox(hwnd, "请输入服务地址 (wss://...)", "提示", MB_OK | MB_ICONWARNING);
                            SetFocus(hServerEdit);
                            break;
                        }
                        if (strlen(currentConfig.listen) == 0) {
                            MessageBox(hwnd, "请输入监听地址 (127.0.0.1:...)", "提示", MB_OK | MB_ICONWARNING);
                            SetFocus(hListenEdit);
                            break;
                        }
                        SaveConfig();
                        StartProcess();
                    }
                    break;

                case ID_STOP_BTN:
                    if (isProcessRunning) StopProcess();
                    break;

                case ID_CLEAR_LOG_BTN:
                    SetWindowText(hLogEdit, "");
                    break;

                case ID_CONN_UP: {
                    char buf[16];
                    GetWindowText(hConnEdit, buf, 16);
                    int val = atoi(buf);
                    if (val < 20) {
                        sprintf(buf, "%d", val + 1);
                        SetWindowText(hConnEdit, buf);
                    }
                    break;
                }

                case ID_CONN_DOWN: {
                    char buf[16];
                    GetWindowText(hConnEdit, buf, 16);
                    int val = atoi(buf);
                    if (val > 1) {
                        sprintf(buf, "%d", val - 1);
                        SetWindowText(hConnEdit, buf);
                    }
                    break;
                }
            }
            break;

        case WM_CLOSE:
            if (isProcessRunning) StopProcess();
            RemoveTrayIcon();
            GetControlValues();
            SaveConfig();
            DestroyWindow(hwnd);
            break;

        case WM_DESTROY:
            RemoveTrayIcon();
            if (hFontUI) DeleteObject(hFontUI);
            if (hFontLog) DeleteObject(hFontLog);
            if (hBrushLog) DeleteObject(hBrushLog);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

void CreateLabelAndEdit(HWND parent, const char* labelText, int x, int y, int w, int h, int editId, HWND* outEdit, BOOL numberOnly) {
    HWND hStatic = CreateWindow("STATIC", labelText, WS_VISIBLE | WS_CHILD | SS_LEFT, 
        x, y + Scale(3), Scale(100), Scale(20), parent, NULL, NULL, NULL);
    SendMessage(hStatic, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    DWORD style = WS_VISIBLE | WS_CHILD | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL;
    if (numberOnly) style |= ES_NUMBER | ES_CENTER;

    *outEdit = CreateWindow("EDIT", "", style, 
        x + Scale(110), y, w - Scale(110), h, parent, (HMENU)(intptr_t)editId, NULL, NULL);
    SendMessage(*outEdit, WM_SETFONT, (WPARAM)hFontUI, TRUE);
    SendMessage(*outEdit, EM_SETLIMITTEXT, (editId == ID_SERVER_EDIT || editId == ID_TOKEN_EDIT) ? MAX_URL_LEN : MAX_SMALL_LEN, 0);
}

// 【关键修复2】布局计算修正
void CreateControls(HWND hwnd) {
    RECT rect;
    GetClientRect(hwnd, &rect);
    int winW = rect.right;
    int margin = Scale(20);
    int groupW = winW - (margin * 2);
    int lineHeight = Scale(30);
    int lineGap = Scale(10);
    int editH = Scale(26);
    int curY = margin;

    // 核心配置
    int group1H = Scale(110);
    HWND hGroup1 = CreateWindow("BUTTON", "核心配置", WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        margin, curY, groupW, group1H, hwnd, NULL, NULL, NULL);
    SendMessage(hGroup1, WM_SETFONT, (WPARAM)hFontUI, TRUE);
    
    int innerY = curY + Scale(25);
    
    // 计算半宽时的间距处理
    int midGap = Scale(20); 
    // 这里的公式是: (总宽度 - 两边padding - 中间间距) / 2
    int halfW = (groupW - Scale(30) - midGap) / 2; 
    
    // 第二列的起始X坐标
    int col2X = margin + Scale(15) + halfW + midGap;

    // 1. 服务地址
    CreateLabelAndEdit(hwnd, "服务地址:", margin + Scale(15), innerY, groupW - Scale(30), editH, ID_SERVER_EDIT, &hServerEdit, FALSE);
    innerY += lineHeight + lineGap;

    // 2. 监听地址
    CreateLabelAndEdit(hwnd, "监听地址:", margin + Scale(15), innerY, halfW, editH, ID_LISTEN_EDIT, &hListenEdit, FALSE);
    
    // 3. 并发连接 (使用计算好的 col2X)
    HWND hLbl = CreateWindow("STATIC", "并发连接:", WS_VISIBLE | WS_CHILD, col2X, innerY + Scale(3), Scale(80), Scale(20), hwnd, NULL, NULL, NULL);
    SendMessage(hLbl, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    int btnSize = Scale(26);
    int numW = Scale(50);
    int numX = col2X + Scale(85);

    hConnEdit = CreateWindow("EDIT", "3", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER | ES_CENTER, 
        numX, innerY, numW, editH, hwnd, (HMENU)ID_CONN_EDIT, NULL, NULL);
    SendMessage(hConnEdit, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    HWND hBtnDown = CreateWindow("BUTTON", "-", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 
        numX + numW + Scale(5), innerY, btnSize, editH, hwnd, (HMENU)ID_CONN_DOWN, NULL, NULL);
    SendMessage(hBtnDown, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    HWND hBtnUp = CreateWindow("BUTTON", "+", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 
        numX + numW + Scale(5) + btnSize + Scale(5), innerY, btnSize, editH, hwnd, (HMENU)ID_CONN_UP, NULL, NULL);
    SendMessage(hBtnUp, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    curY += group1H + Scale(15);

    // 高级选项
    int group2H = Scale(155);
    HWND hGroup2 = CreateWindow("BUTTON", "高级选项 (可选)", WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        margin, curY, groupW, group2H, hwnd, NULL, NULL, NULL);
    SendMessage(hGroup2, WM_SETFONT, (WPARAM)hFontUI, TRUE);
    innerY = curY + Scale(25);

    // 4. 身份令牌
    CreateLabelAndEdit(hwnd, "身份令牌:", margin + Scale(15), innerY, groupW - Scale(30), editH, ID_TOKEN_EDIT, &hTokenEdit, FALSE);
    innerY += lineHeight + lineGap;

    // 5. 指定IP 和 DNS
    CreateLabelAndEdit(hwnd, "指定IP:", margin + Scale(15), innerY, halfW, editH, ID_IP_EDIT, &hIpEdit, FALSE);
    // 修复: 使用 col2X 确保对齐且不溢出
    CreateLabelAndEdit(hwnd, "DNS服务器:", col2X, innerY, halfW, editH, ID_DNS_EDIT, &hDnsEdit, FALSE);
    innerY += lineHeight + lineGap;

    // 6. ECH
    CreateLabelAndEdit(hwnd, "ECH域名:", margin + Scale(15), innerY, groupW - Scale(30), editH, ID_ECH_EDIT, &hEchEdit, FALSE);

    curY += group2H + Scale(15);

    // 按钮栏
    int btnW = Scale(120);
    int btnH = Scale(38);
    int btnGap = Scale(20);
    int startX = margin;

    hStartBtn = CreateWindow("BUTTON", "启动代理", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        startX, curY, btnW, btnH, hwnd, (HMENU)ID_START_BTN, NULL, NULL);
    SendMessage(hStartBtn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    hStopBtn = CreateWindow("BUTTON", "停止", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        startX + btnW + btnGap, curY, btnW, btnH, hwnd, (HMENU)ID_STOP_BTN, NULL, NULL);
    SendMessage(hStopBtn, WM_SETFONT, (WPARAM)hFontUI, TRUE);
    EnableWindow(hStopBtn, FALSE);

    HWND hClrBtn = CreateWindow("BUTTON", "清空日志", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        rect.right - margin - btnW, curY, btnW, btnH, hwnd, (HMENU)ID_CLEAR_LOG_BTN, NULL, NULL);
    SendMessage(hClrBtn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    curY += btnH + Scale(15);

    // 日志区域
    HWND hLogLabel = CreateWindow("STATIC", "运行日志:", WS_VISIBLE | WS_CHILD, 
        margin, curY, Scale(100), Scale(20), hwnd, NULL, NULL, NULL);
    SendMessage(hLogLabel, WM_SETFONT, (WPARAM)hFontUI, TRUE);
    
    curY += Scale(25);

    hLogEdit = CreateWindow("EDIT", "", 
        WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 
        margin, curY, winW - (margin * 2), Scale(200), hwnd, (HMENU)ID_LOG_EDIT, NULL, NULL);
    SendMessage(hLogEdit, WM_SETFONT, (WPARAM)hFontLog, TRUE);
    SendMessage(hLogEdit, EM_SETLIMITTEXT, 0, 0);
}

void GetControlValues() {
    char buf[MAX_URL_LEN];
    GetWindowText(hServerEdit, buf, sizeof(buf));
    if (strlen(buf) > 0 && strncmp(buf, "wss://", 6) != 0) snprintf(currentConfig.server, sizeof(currentConfig.server), "wss://%s", buf);
    else strcpy(currentConfig.server, buf);

    GetWindowText(hListenEdit, buf, sizeof(buf));
    if (strlen(buf) > 0 && strncmp(buf, "proxy://", 8) != 0) snprintf(currentConfig.listen, sizeof(currentConfig.listen), "proxy://%s", buf);
    else strcpy(currentConfig.listen, buf);

    GetWindowText(hTokenEdit, currentConfig.token, sizeof(currentConfig.token));
    GetWindowText(hIpEdit, currentConfig.ip, sizeof(currentConfig.ip));
    GetWindowText(hDnsEdit, currentConfig.dns, sizeof(currentConfig.dns));
    GetWindowText(hEchEdit, currentConfig.ech, sizeof(currentConfig.ech));

    char connBuf[32];
    GetWindowText(hConnEdit, connBuf, 32);
    currentConfig.connections = atoi(connBuf);
    if (currentConfig.connections < 1) currentConfig.connections = 1;
}

void SetControlValues() {
    if (strncmp(currentConfig.server, "wss://", 6) == 0) SetWindowText(hServerEdit, currentConfig.server + 6);
    else SetWindowText(hServerEdit, currentConfig.server);

    if (strncmp(currentConfig.listen, "proxy://", 8) == 0) SetWindowText(hListenEdit, currentConfig.listen + 8);
    else SetWindowText(hListenEdit, currentConfig.listen);

    SetWindowText(hTokenEdit, currentConfig.token);
    SetWindowText(hIpEdit, currentConfig.ip);
    SetWindowText(hDnsEdit, currentConfig.dns);
    SetWindowText(hEchEdit, currentConfig.ech);

    char connBuf[32];
    sprintf(connBuf, "%d", currentConfig.connections);
    SetWindowText(hConnEdit, connBuf);
}

void StartProcess() {
    char cmdLine[MAX_CMD_LEN];
    char exePath[MAX_PATH] = "ech-tunnel.exe";
    
    if (GetFileAttributes(exePath) == INVALID_FILE_ATTRIBUTES) {
        AppendLog("错误: 找不到 ech-tunnel.exe 文件!\r\n");
        return;
    }
    
    snprintf(cmdLine, MAX_CMD_LEN, "\"%s\"", exePath);
    #define APPEND_ARG(flag, val) if(strlen(val) > 0) { strcat(cmdLine, " " flag " \""); strcat(cmdLine, val); strcat(cmdLine, "\""); }

    APPEND_ARG("-f", currentConfig.server);
    APPEND_ARG("-l", currentConfig.listen);
    APPEND_ARG("-token", currentConfig.token);
    APPEND_ARG("-ip", currentConfig.ip);
    
    if (strlen(currentConfig.dns) > 0 && strcmp(currentConfig.dns, "119.29.29.29:53") != 0) {
        APPEND_ARG("-dns", currentConfig.dns);
    }
    if (strlen(currentConfig.ech) > 0 && strcmp(currentConfig.ech, "cloudflare-ech.com") != 0) {
        APPEND_ARG("-ech", currentConfig.ech);
    }
    
    if (currentConfig.connections != 3) {
        char nBuf[32]; sprintf(nBuf, " -n %d", currentConfig.connections);
        strcat(cmdLine, nBuf);
    }

    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return;

    STARTUPINFO si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE;

    if (CreateProcess(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &processInfo)) {
        CloseHandle(hWrite);
        hLogPipe = hRead;
        hLogThread = CreateThread(NULL, 0, LogReaderThread, NULL, 0, NULL);
        isProcessRunning = TRUE;
        EnableWindow(hStartBtn, FALSE);
        EnableWindow(hStopBtn, TRUE);
        EnableWindow(hServerEdit, FALSE);
        EnableWindow(hListenEdit, FALSE);
        AppendLog("[系统] 进程已启动...\r\n");
    } else {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        AppendLog("[错误] 启动失败，请检查配置。\r\n");
    }
}

void StopProcess() {
    isProcessRunning = FALSE;

    if (hLogPipe) {
        CloseHandle(hLogPipe);
        hLogPipe = NULL;
    }

    if (processInfo.hProcess) {
        TerminateProcess(processInfo.hProcess, 0);
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
        processInfo.hProcess = NULL;
    }

    if (hLogThread) {
        if (WaitForSingleObject(hLogThread, 500) == WAIT_TIMEOUT) {
            TerminateThread(hLogThread, 0);
        }
        CloseHandle(hLogThread);
        hLogThread = NULL;
    }
    
    if (IsWindow(hMainWindow)) {
        EnableWindow(hStartBtn, TRUE);
        EnableWindow(hStopBtn, FALSE);
        EnableWindow(hServerEdit, TRUE);
        EnableWindow(hListenEdit, TRUE);
        AppendLog("[系统] 进程已停止。\r\n");
    }
}

void AppendLogAsync(const char* text) {
    if (!text) return;
    char* msgCopy = strdup(text); 
    if (msgCopy) {
        if (!PostMessage(hMainWindow, WM_APPEND_LOG, 0, (LPARAM)msgCopy)) {
            free(msgCopy);
        }
    }
}

DWORD WINAPI LogReaderThread(LPVOID lpParam) {
    (void)lpParam;
    char buf[1024];
    char u8Buf[2048];
    DWORD read;
    
    while (isProcessRunning && hLogPipe) {
        if (ReadFile(hLogPipe, buf, sizeof(buf)-1, &read, NULL) && read > 0) {
            buf[read] = 0;
            int wLen = MultiByteToWideChar(CP_UTF8, 0, buf, -1, NULL, 0);
            if (wLen > 0) {
                WCHAR* wBuf = (WCHAR*)malloc(wLen * sizeof(WCHAR));
                if (wBuf) {
                    MultiByteToWideChar(CP_UTF8, 0, buf, -1, wBuf, wLen);
                    WideCharToMultiByte(CP_ACP, 0, wBuf, -1, u8Buf, sizeof(u8Buf), NULL, NULL);
                    AppendLogAsync(u8Buf);
                    free(wBuf);
                }
            } else {
                AppendLogAsync(buf);
            }
        } else {
            break; 
        }
    }
    return 0;
}

void AppendLog(const char* text) {
    if (!IsWindow(hLogEdit)) return;
    int len = GetWindowTextLength(hLogEdit);
    SendMessage(hLogEdit, EM_SETSEL, len, len);
    SendMessage(hLogEdit, EM_REPLACESEL, FALSE, (LPARAM)text);
}

void SaveConfig() {
    FILE* f = fopen("config.ini", "w");
    if (!f) return;
    fprintf(f, "[ECHTunnel]\nserver=%s\nlisten=%s\ntoken=%s\nip=%s\ndns=%s\nech=%s\nconnections=%d\n",
        currentConfig.server, currentConfig.listen, currentConfig.token, 
        currentConfig.ip, currentConfig.dns, currentConfig.ech, currentConfig.connections);
    fclose(f);
}

void LoadConfig() {
    FILE* f = fopen("config.ini", "r");
    if (!f) return;
    char line[MAX_URL_LEN];
    while (fgets(line, sizeof(line), f)) {
        char* val = strchr(line, '=');
        if (!val) continue;
        *val++ = 0;
        if (val[strlen(val)-1] == '\n') val[strlen(val)-1] = 0;

        if (!strcmp(line, "server")) strcpy(currentConfig.server, val);
        else if (!strcmp(line, "listen")) strcpy(currentConfig.listen, val);
        else if (!strcmp(line, "token")) strcpy(currentConfig.token, val);
        else if (!strcmp(line, "ip")) strcpy(currentConfig.ip, val);
        else if (!strcmp(line, "dns")) strcpy(currentConfig.dns, val);
        else if (!strcmp(line, "ech")) strcpy(currentConfig.ech, val);
        else if (!strcmp(line, "connections")) currentConfig.connections = atoi(val);
    }
    fclose(f);
}