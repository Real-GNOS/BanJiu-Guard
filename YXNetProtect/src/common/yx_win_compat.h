// BanJiu-Guard - 跨平台兼容层
// 在非 Windows 平台提供 common/gui/service 所需的最小 Win32 类型与 API 子集，
// 使 PE 扫描引擎（启发式 + LightGBM 特征提取）可在 Linux 上原样复用。
// Windows 平台下本文件为空实现（由源文件自行包含 <windows.h>）。
#pragma once

#ifdef _WIN32

// Windows：真实 windows.h 由调用方包含，此处仅提供跨平台文件打开辅助
#include <fstream>
#include <string>

namespace yx {
// 以二进制方式打开文件（Windows 的 std::ifstream 原生接受 std::wstring）
inline std::ifstream OpenBinary(const std::wstring& path, std::ios::openmode mode)
{
    return std::ifstream(path.c_str(), mode);
}
} // namespace yx
using yx::OpenBinary;

#else // ------------------------- 非 Windows -------------------------

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <fstream>
#include <chrono>
#include <cwchar>
#include <unistd.h>
#include <limits.h>

// ---- 基础类型别名（与 Win32 布局一致）----
using BYTE      = uint8_t;
using WORD      = uint16_t;
using DWORD     = uint32_t;
using LONG      = int32_t;
using ULONG     = uint32_t;
using BOOL      = int;
using UINT      = unsigned int;
using ULONGLONG = uint64_t;
using LONGLONG  = int64_t;
using WCHAR     = wchar_t;
using HANDLE    = void*;

#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#ifndef CP_UTF8
#define CP_UTF8 65001
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

namespace yx {

// ---- 宽字符 <-> UTF-8（Linux 上 wchar_t 为 UTF-32）----
inline std::string WideToUtf8(const wchar_t* src)
{
    std::string out;
    if (!src) return out;
    for (const wchar_t* p = src; *p; ++p) {
        uint32_t c = (uint32_t)*p;
        if (c < 0x80) {
            out += (char)c;
        } else if (c < 0x800) {
            out += (char)(0xC0 | (c >> 6));
            out += (char)(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            out += (char)(0xE0 | (c >> 12));
            out += (char)(0x80 | ((c >> 6) & 0x3F));
            out += (char)(0x80 | (c & 0x3F));
        } else {
            out += (char)(0xF0 | (c >> 18));
            out += (char)(0x80 | ((c >> 12) & 0x3F));
            out += (char)(0x80 | ((c >> 6) & 0x3F));
            out += (char)(0x80 | (c & 0x3F));
        }
    }
    return out;
}

inline std::wstring Utf8ToWide(const char* src)
{
    std::wstring out;
    if (!src) return out;
    const unsigned char* p = (const unsigned char*)src;
    while (*p) {
        uint32_t c = 0;
        int extra = 0;
        if (*p < 0x80)      { c = *p;         extra = 0; }
        else if ((*p & 0xE0) == 0xC0) { c = *p & 0x1F; extra = 1; }
        else if ((*p & 0xF0) == 0xE0) { c = *p & 0x0F; extra = 2; }
        else if ((*p & 0xF8) == 0xF0) { c = *p & 0x07; extra = 3; }
        else { ++p; continue; }
        ++p;
        for (int i = 0; i < extra && *p; ++i, ++p) c = (c << 6) | (*p & 0x3F);
        out += (wchar_t)c;
    }
    return out;
}

// 宽字符路径 -> 本机路径窄串（Linux 文件系统按 UTF-8 寻址）
inline std::string PathNarrow(const std::wstring& w) { return WideToUtf8(w.c_str()); }
inline std::wstring PathWide(const std::string& s)  { return Utf8ToWide(s.c_str()); }

// 以二进制方式打开文件（Linux 的 std::ifstream 不接受 std::wstring）
inline std::ifstream OpenBinary(const std::wstring& path, std::ios::openmode mode)
{
    return std::ifstream(PathNarrow(path), mode);
}

// ---- Win32 API 子集：可移植实现 ----
// GetModuleFileNameW(nullptr, buf, n)：取当前可执行文件路径
inline DWORD GetModuleFileNameW(void* /*hModule*/, wchar_t* buf, DWORD n)
{
    if (!buf || n == 0) return 0;
    char tmp[PATH_MAX] = { 0 };
    ssize_t len = ::readlink("/proc/self/exe", tmp, sizeof(tmp) - 1);
    if (len <= 0) { buf[0] = L'\0'; return 0; }
    tmp[len] = '\0';
    std::wstring w = Utf8ToWide(tmp);
    if (w.size() >= n) w.resize(n - 1);
    std::wmemcpy(buf, w.c_str(), w.size());
    buf[w.size()] = L'\0';
    return (DWORD)w.size();
}

// WideCharToMultiByte(CP_UTF8, ...)：仅实现 CP_UTF8、cbMultiByte=0/-1 的常用形态
inline int WideCharToMultiByte(unsigned /*cp*/, DWORD /*flags*/, const wchar_t* src,
                               int srcLen, char* dst, int dstLen, const char* /*defCh*/, BOOL* /*usedDef*/)
{
    if (!src) return 0;
    std::wstring w(src, srcLen < 0 ? wcslen(src) : (size_t)srcLen);
    if (srcLen < 0) w += L'\0';               // 保留结尾 NUL 的语义
    std::string u8 = WideToUtf8(w.c_str());
    if (srcLen < 0 && (w.empty() || w.back() != L'\0')) u8 += '\0';
    int need = (int)WideToUtf8(w.c_str()).size() + (srcLen < 0 ? 1 : 0);
    if (!dst || dstLen == 0) return need;
    int copy = need < dstLen ? need : dstLen;
    if (copy > 0) {
        std::string s = WideToUtf8(w.c_str());
        memcpy(dst, s.c_str(), s.size() < (size_t)copy ? s.size() : (size_t)copy - 1);
        dst[copy - 1] = '\0';
    }
    return need;
}

// GetTickCount()：自进程启动以来的毫秒数
inline DWORD GetTickCount()
{
    using namespace std::chrono;
    static const steady_clock::time_point t0 = steady_clock::now();
    return (DWORD)duration_cast<milliseconds>(steady_clock::now() - t0).count();
}

inline ULONGLONG GetTickCount64()
{
    using namespace std::chrono;
    static const steady_clock::time_point t0 = steady_clock::now();
    return (ULONGLONG)duration_cast<milliseconds>(steady_clock::now() - t0).count();
}

} // namespace yx

// 源码中直接以全局名调用（保持与 Windows 源码一致）
using yx::PathNarrow;
using yx::PathWide;
using yx::OpenBinary;
using yx::GetModuleFileNameW;
using yx::WideCharToMultiByte;
using yx::GetTickCount;
using yx::GetTickCount64;

#endif // _WIN32
