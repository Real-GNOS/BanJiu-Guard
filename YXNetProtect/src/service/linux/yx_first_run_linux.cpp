// BanJiu-Guard - 首次运行引导 & 完全防护权限管理（Linux 实现）
// 与 Windows 版概念的对应关系：
//   注册表 HasRunBefore 标记      -> XDG 配置目录下的标记文件
//   bcdedit /set testsigning on   -> setcap 给可执行文件授予 CAP_SYS_ADMIN
//                                     （fanotify 同步拦截所需权限，需 polkit 提权）
//   测试签名模式是否开启          -> 能否成功初始化 fanotify 权限事件
//   计划任务 ONSTART 自启         -> ~/.config/autostart/*.desktop（XDG autostart）

#include "../yx_first_run.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/fanotify.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>

#include "../common/yx_win_compat.h"

namespace fs = std::filesystem;

namespace yx {
namespace {

std::string HomeDir()
{
    const char* h = ::getenv("HOME");
    return (h && *h) ? h : "/tmp";
}

std::string ConfigDirPath()
{
    const char* x = ::getenv("XDG_CONFIG_HOME");
    std::string base = (x && *x) ? x : (HomeDir() + "/.config");
    return base + "/BanJiu-Guard";
}

std::string MarkerPath() { return ConfigDirPath() + "/has_run_before"; }

std::string AutostartPath() { return HomeDir() + "/.config/autostart/banjia-guard.desktop"; }

// 当前可执行文件路径（UTF-8）
std::string SelfExe()
{
    wchar_t buf[4096] = { 0 };
    yx::GetModuleFileNameW(nullptr, buf, 4095);
    return PathNarrow(buf);
}

// 是否具备执行 fanotify 同步拦截的权限（root 或 CAP_SYS_ADMIN）
bool FanotifyCapable()
{
    int fd = ::fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY);
    if (fd < 0) return false;
    ::close(fd);
    return true;
}

} // namespace

bool FirstRunManager::HasRunBefore()
{
    std::ifstream f(MarkerPath());
    return f.is_open();
}

bool FirstRunManager::MarkHasRun()
{
    std::error_code ec;
    fs::create_directories(ConfigDirPath(), ec);
    std::ofstream f(MarkerPath(), std::ios::trunc);
    return f.is_open();
}

// Linux：以"能否执行 fanotify 同步拦截"作为完全防护是否就绪的判据
bool FirstRunManager::IsTestSigningEnabled()
{
    return FanotifyCapable();
}

// Linux：授予可执行文件 CAP_SYS_ADMIN（对应 Windows 的开启测试签名模式）
// 需要系统安装 setcap（libcap2-bin）与 polkit（pkexec），否则返回 false
bool FirstRunManager::EnableTestSigning()
{
    if (FanotifyCapable()) return true;

    std::string exe = SelfExe();
    if (exe.empty()) return false;

    std::string cmd =
        "pkexec setcap cap_sys_admin,cap_dac_read_search,cap_dac_override+ep '" +
        exe + "' 2>/dev/null";
    int rc = ::system(cmd.c_str());
    if (rc != 0) {
        // 退回直接尝试（已 root 时无需 setcap）
        return FanotifyCapable();
    }
    return FanotifyCapable();
}

bool FirstRunManager::DisableTestSigning()
{
    std::string exe = SelfExe();
    if (exe.empty()) return false;
    std::string cmd = "pkexec setcap -r '" + exe + "' 2>/dev/null";
    int rc = ::system(cmd.c_str());
    return rc == 0 || !FanotifyCapable();
}

bool FirstRunManager::IsElevated()
{
    if (::geteuid() == 0) return true;
    // 具备等价权限（文件能力）时同样视为已提权
    std::string exe = SelfExe();
    if (exe.empty()) return false;
    char buf[64];
    ssize_t n = ::getxattr(exe.c_str(), "security.capability", buf, sizeof(buf));
    return n > 0;
}

bool FirstRunManager::IsAutoStartEnabled()
{
    std::ifstream f(AutostartPath());
    return f.is_open();
}

bool FirstRunManager::EnableAutoStart(const std::wstring& exePath, std::wstring& errMsg)
{
    std::string exe = PathNarrow(exePath);
    if (exe.empty()) exe = SelfExe();

    std::string dir = HomeDir() + "/.config/autostart";
    std::error_code ec;
    fs::create_directories(dir, ec);

    std::ofstream f(AutostartPath(), std::ios::trunc);
    if (!f.is_open()) {
        errMsg = L"无法写入 " + PathWide(AutostartPath());
        return false;
    }
    f << "[Desktop Entry]\n"
      << "Type=Application\n"
      << "Name=BanJiu-Guard\n"
      << "Comment=BanJiu-Guard 反银狐木马防护（开机自启）\n"
      << "Exec=" << exe << "\n"
      << "Terminal=false\n"
      << "X-GNOME-Autostart-enabled=true\n";
    return true;
}

bool FirstRunManager::DisableAutoStart(std::wstring& errMsg)
{
    std::error_code ec;
    if (!fs::remove(AutostartPath(), ec) && ec) {
        errMsg = L"删除 " + PathWide(AutostartPath()) + L" 失败：" + PathWide(ec.message());
        return false;
    }
    return true;
}

} // namespace yx
