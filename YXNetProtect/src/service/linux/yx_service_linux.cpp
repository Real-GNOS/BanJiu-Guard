// BanJiu-Guard - 实时防护服务的 Linux 实现
// 与 Windows 版（内核 Minifilter + SCM 服务）等价的用户态实现：
//  1. fanotify(FAN_OPEN_EXEC_PERM) 同步拦截可执行文件启动（对应进程创建回调）
//     —— 命中威胁时直接回 FAN_DENY，进程根本不会创建
//  2. /proc/net/tcp{,6} 轮询出站连接 -> 银狐 C2 黑名单（对应网络回调）
//  3. cron / systemd 单元轮询 -> 持久化项检测（对应计划任务回调）
//  4. 复用 common 的规则引擎 / 启发式 / LightGBM ML 打分
//  5. 隔离区、处置、配置持久化与 Windows 版语义一致
//
// 权限说明：fanotify 的同步拦截需要 root 或 CAP_SYS_ADMIN；
//           无权限时自动降级为被动模式（仅轮询检测 + 手动扫描）。
//
// Linux 版差异（v1）：
//  - 无内核驱动：IsDriverLoaded() 表示"fanotify 同步拦截是否可用"
//  - 文件落地实时扫描（minifilter 写入回调）暂未移植，落地文件由
//    执行前扫描（FAN_OPEN_EXEC_PERM）与手动扫描覆盖
//  - 持久化项只上报不自动删除（cron/systemd 条目误删代价过高）

#include "../yx_service.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace yx {
namespace {

// ===========================================================================
// 路径与环境
// ===========================================================================
std::string HomeDir()
{
    const char* h = ::getenv("HOME");
    if (h && *h) return h;
    return "/tmp";
}

std::string ConfigDirPath()
{
    const char* x = ::getenv("XDG_CONFIG_HOME");
    std::string base = (x && *x) ? x : (HomeDir() + "/.config");
    return base + "/BanJiu-Guard";
}

std::string DataDirPath()
{
    const char* x = ::getenv("XDG_DATA_HOME");
    std::string base = (x && *x) ? x : (HomeDir() + "/.local/share");
    return base + "/BanJiu-Guard";
}

// 当前可执行文件所在目录
std::wstring ExeDirW()
{
    wchar_t buf[4096] = { 0 };
    yx::GetModuleFileNameW(nullptr, buf, 4095);
    std::error_code ec;
    fs::path p = fs::path(buf).parent_path();
    (void)ec;
    return p.wstring();
}

// 配置文件路径（跨平台统一 XDG 路径，避免写入 /usr/bin 等只读安装目录）
std::wstring ConfigFilePathW()
{
    return PathWide(ConfigDirPath() + "/config.ini");
}

bool PathExists(const std::wstring& p)
{
    std::error_code ec;
    return fs::exists(p, ec);
}

// ===========================================================================
// fd -> 路径
// ===========================================================================
bool FdToPath(int fd, std::string& out)
{
    if (fd < 0) return false;
    char link[64];
    ::snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    char buf[4096];
    ssize_t n = ::readlink(link, buf, sizeof(buf) - 1);
    if (n <= 0) return false;
    buf[n] = '\0';
    out = buf;
    // 内核对已删除文件会追加 " (deleted)"
    const char* del = " (deleted)";
    size_t dl = ::strlen(del);
    if (out.size() > dl && out.compare(out.size() - dl, dl, del) == 0)
        out.erase(out.size() - dl);
    return !out.empty();
}

// ===========================================================================
// 隔离后缀与元数据（与 Windows 版兼容：.quarantined 后缀 + 旁路 .path 记录原路径）
// ===========================================================================
constexpr const wchar_t* kQuarSuffix = L".quarantined";

bool HasQuarSuffix(const std::wstring& n)
{
    if (n.size() < ::wcslen(kQuarSuffix)) return false;
    return n.compare(n.size() - ::wcslen(kQuarSuffix), ::wcslen(kQuarSuffix), kQuarSuffix) == 0;
}

std::wstring StripQuarSuffixes(std::wstring n)
{
    while (HasQuarSuffix(n))
        n.erase(n.size() - ::wcslen(kQuarSuffix));
    return n;
}

std::wstring MetaPathOf(const std::wstring& quarPath) { return quarPath + L".path"; }

void WriteQuarantineMeta(const std::wstring& quarPath, const std::wstring& originalPath)
{
    std::ofstream f(PathNarrow(MetaPathOf(quarPath)), std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return;
    std::string u8 = PathNarrow(originalPath);
    f.write(u8.data(), (std::streamsize)u8.size());
}

bool ReadQuarantineMeta(const std::wstring& quarPath, std::wstring& originalPath)
{
    std::ifstream f(PathNarrow(MetaPathOf(quarPath)), std::ios::binary);
    if (!f.is_open()) return false;
    std::string u8((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (u8.empty()) return false;
    originalPath = PathWide(u8);
    return true;
}

// ===========================================================================
// /proc 工具
// ===========================================================================
bool IsPidStr(const char* s)
{
    if (!s || !*s) return false;
    for (const char* p = s; *p; ++p)
        if (*p < '0' || *p > '9') return false;
    return true;
}

// 查找正在运行某文件的进程 PID（/proc/*/exe 与目标路径一致）
DWORD FindPidByExePath(const std::wstring& exePath)
{
    std::error_code ec;
    fs::path target = fs::weakly_canonical(exePath, ec);
    if (ec) target = fs::path(PathNarrow(exePath));

    DIR* d = ::opendir("/proc");
    if (!d) return 0;
    DWORD found = 0;
    while (struct dirent* e = ::readdir(d)) {
        if (!IsPidStr(e->d_name)) continue;
        char link[64];
        ::snprintf(link, sizeof(link), "/proc/%s/exe", e->d_name);
        char buf[4096];
        ssize_t n = ::readlink(link, buf, sizeof(buf) - 1);
        if (n <= 0) continue;
        buf[n] = '\0';
        const char* del = " (deleted)";
        std::string exe(buf);
        size_t dl = ::strlen(del);
        if (exe.size() > dl && exe.compare(exe.size() - dl, dl, del) == 0)
            exe.erase(exe.size() - dl);

        std::error_code ec2;
        fs::path cand = fs::weakly_canonical(fs::path(exe), ec2);
        if (ec2) cand = fs::path(exe);
        if (cand == target) { found = (DWORD)::atoi(e->d_name); break; }
    }
    ::closedir(d);
    return found;
}

// ===========================================================================
// /proc/net/tcp 解析：把 "0100007F:1F90" 形式的十六进制地址转成点分 IP
// ===========================================================================
std::string HexAddrToIp(const std::string& rem)
{
    size_t colon = rem.find(':');
    if (colon == std::string::npos) return {};
    std::string h = rem.substr(0, colon);

    auto bytesFromHex8 = [](const std::string& eight) -> std::string {
        // /proc/net/tcp 以小端字（host byte order）书写：0100007F -> 127.0.0.1
        uint32_t v = (uint32_t)::strtoul(eight.c_str(), nullptr, 16);
        char out[32];
        ::snprintf(out, sizeof(out), "%u.%u.%u.%u",
                   v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF);
        return out;
    };

    if (h.size() == 8) return bytesFromHex8(h);              // IPv4
    if (h.size() == 32) {                                     // IPv6
        // ::ffff:a.b.c.d 的 v4 映射地址：前 24 个 hex 为 0、其后为 ffff
        std::string prefix = h.substr(0, 24);
        std::string ffff = h.substr(24, 4);
        if (prefix.find_first_not_of('0') == std::string::npos &&
            (ffff == "ffff" || ffff == "FFFF")) {
            return bytesFromHex8(h.substr(28, 8));
        }
        return {};  // 纯 IPv6：银狐 IOC 为 IPv4，暂不匹配
    }
    return {};
}

// ===========================================================================
// 可执行格式判定（PE MZ / ELF 魔数）
// ===========================================================================
// 向 fanotify 回应权限事件（FAN_ALLOW / FAN_DENY）
void FanotifyRespond(int fanFd, int eventFd, uint32_t response)
{
    struct fanotify_response r;
    r.fd = eventFd;
    r.response = response;
    ssize_t ignored = ::write(fanFd, &r, sizeof(r));
    (void)ignored;
}

enum class ExeFormat { Unknown, Pe, Elf };

ExeFormat DetectFormat(const std::wstring& path)
{
    std::ifstream f = OpenBinary(path, std::ios::binary);
    if (!f.is_open()) return ExeFormat::Unknown;
    unsigned char magic[4] = { 0 };
    f.read((char*)magic, 4);
    if (f.gcount() < 4) return ExeFormat::Unknown;
    if (magic[0] == 'M' && magic[1] == 'Z') return ExeFormat::Pe;
    if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
        return ExeFormat::Elf;
    return ExeFormat::Unknown;
}

} // namespace

// ===========================================================================
// 构造 / 析构
// ===========================================================================
ProtectionService::ProtectionService()
{
    std::error_code ec;
    ::fs::create_directories(ConfigDirPath(), ec);
    ::fs::create_directories(DataDirPath(), ec);
    m_quarantineDir = PathWide(DataDirPath() + "/Quarantine");
    m_stats = Stats{};
}

ProtectionService::~ProtectionService()
{
    Shutdown();
}

// ===========================================================================
// 初始化 / 启停
// ===========================================================================
bool ProtectionService::Initialize()
{
    LoadSettingsFromFile();
    EnsureQuarantineDir();

    Log(L"[初始化] BanJiu-Guard Linux 版 —— 用户态实时防护（fanotify），无内核驱动");
    Log(L"[初始化] 隔离区: " + m_quarantineDir);
    Log(L"[初始化] 配置文件: " + ConfigFilePathW());

    if (m_ml.Load()) {
        Log(L"[初始化] LightGBM ML 模型加载成功，启用「启发式 70% + ML 30%」融合打分");
    } else {
        Log(L"[初始化] 未找到 ML 模型，检测退化为纯启发式"
            L"（可将 lgbm_detector.txt 置于可执行文件目录的 models/ 下）");
    }
    return true;
}

void ProtectionService::Shutdown()
{
    Stop();
}

bool ProtectionService::Start()
{
    if (m_running.exchange(true)) return true;
    m_monitorThread = std::thread(&ProtectionService::MonitorThreadProc, this);
    m_driverThread  = std::thread(&ProtectionService::DriverMessageThreadProc, this);
    Log(L"[服务] 监控已启动");
    return true;
}

void ProtectionService::Stop()
{
    m_running.store(false);
    if (m_monitorThread.joinable()) m_monitorThread.join();
    if (m_driverThread.joinable())  m_driverThread.join();
    m_driverLoaded = false;
}

void ProtectionService::SetCallbacks(ServiceCallbacks cb)
{
    std::lock_guard<std::mutex> lk(m_mutex);
    m_callbacks = std::move(cb);
}

void ProtectionService::Log(const std::wstring& msg)
{
    ServiceCallbacks cb;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        cb = m_callbacks;
    }
    if (cb.onLog) cb.onLog(msg);
    // 无 GUI 场景（命令行/日志重定向）也留一份到 stderr
    ::fprintf(stderr, "%s\n", PathNarrow(msg).c_str());
}

// ===========================================================================
// 监控线程：fanotify 执行拦截 + 周期轮询
// ===========================================================================
void ProtectionService::MonitorThreadProc()
{
    // ---------- 初始化 fanotify ----------
    int fanFd = -1;
    fanFd = ::fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK |
                            FAN_UNLIMITED_QUEUE,
                            O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fanFd >= 0) {
        // 只挂 FAN_OPEN_EXEC_PERM：事件量小（仅进程执行），且可同步否决。
        // 覆盖整个文件系统根（FAN_MARK_FILESYSTEM），失败则回退到挂载点标记。
        uint64_t mask = FAN_OPEN_EXEC_PERM;
        if (::fanotify_mark(fanFd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask,
                            AT_FDCWD, "/") != 0) {
            if (::fanotify_mark(fanFd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask,
                                AT_FDCWD, "/") != 0) {
                int err = errno;
                ::close(fanFd);
                fanFd = -1;
                errno = err;
            }
        }
    }

    if (fanFd >= 0) {
        m_driverLoaded = true;
        Log(L"[实时防护] fanotify 执行前同步拦截已启用（进程创建前判定，命中直接拒绝执行）");
    } else {
        m_driverLoaded = false;
        Log(L"[实时防护] 无法初始化 fanotify（errno=" + std::to_wstring(errno) +
            L"），已降级为被动模式：仍会轮询 C2 连接与持久化项，"
            L"执行前拦截不可用。以 root 或授予 CAP_SYS_ADMIN 运行可启用。");
    }

    // ---------- 事件循环 ----------
    std::vector<char> buf(64 * 1024);
    auto lastPoll = std::chrono::steady_clock::now();

    // 执行前扫描准入条件
    auto shouldScan = [this](const std::wstring& wp) -> bool {
        ProtectSettings settings = GetProtectSettings();
        if (!settings.processStartScan) return false;
        std::error_code ec;
        if (!fs::is_regular_file(wp, ec)) return false;
        uintmax_t sz = fs::file_size(wp, ec);
        if (ec || sz == 0 || sz > 64ull * 1024 * 1024) return false;
        if (wp.rfind(m_quarantineDir, 0) == 0) return false;      // 跳过隔离区
        if (fs::path(wp).parent_path() == fs::path(ExeDirW()))
            return false;                                          // 跳过自身目录（自身已可信）
        std::string narrow = PathNarrow(wp);
        if (narrow.rfind("/proc/", 0) == 0 || narrow.rfind("/sys/", 0) == 0 ||
            narrow.rfind("/dev/", 0) == 0)
            return false;
        struct stat st;
        if (::stat(narrow.c_str(), &st) != 0) return false;
        if (!(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) return false;
        ExeFormat fmt = DetectFormat(wp);
        return fmt == ExeFormat::Pe || fmt == ExeFormat::Elf;
    };

    while (m_running.load()) {
        bool didWork = false;

        if (fanFd >= 0) {
            ssize_t n = ::read(fanFd, buf.data(), buf.size());
            if (n > 0) {
                didWork = true;
                size_t off = 0;
                while (off + sizeof(fanotify_event_metadata) <= (size_t)n) {
                    auto* ev = reinterpret_cast<fanotify_event_metadata*>(buf.data() + off);
                    if (ev->event_len < sizeof(fanotify_event_metadata))
                        break;

                    if (ev->fd >= 0) {
                        int efd = ev->fd;
                        if (ev->mask & FAN_OPEN_EXEC_PERM) {
                            std::string p;
                            int resp = FAN_ALLOW;
                            bool answered = false;
                            if (FdToPath(efd, p)) {
                                std::wstring wp = PathWide(p);
                                if (shouldScan(wp)) {
                                    HeuristicResult heur = m_heuristic.ScanFile(wp);
                                    MlResult mlr = m_ml.ScanFile(wp);
                                    FusionResult fused = FuseScores(heur.score, mlr);

                                    {
                                        std::lock_guard<std::mutex> lk(m_mutex);
                                        m_stats.FilesScanned++;
                                    }

                                    if (fused.score >= 50) {
                                        {
                                            std::lock_guard<std::mutex> lk(m_mutex);
                                            m_stats.FilesBlocked++;
                                        }

                                        RuleHit hit;
                                        hit.category = RuleCategory::Heuristic;
                                        hit.level = ThreatLevel::High;
                                        hit.subject = wp;
                                        hit.object = wp;
                                        hit.protectedObject = false;
                                        hit.description =
                                            L"执行前扫描发现可疑文件（融合分数 " +
                                            std::to_wstring(fused.score) + L"）: " + wp +
                                            L" —— 已拒绝启动。" +
                                            PathWide(heur.reason);

                                        // 先回应内核（进程被拒绝创建），再走处置流程
                                        FanotifyRespond(fanFd, efd, FAN_DENY);
                                        answered = true;
                                        HandleThreat(hit);
                                    } else if (fused.score >= 30) {
                                        Log(L"[扫描] 可疑（分数 " +
                                            std::to_wstring(fused.score) +
                                            L"）已放行: " + wp +
                                            L" —— " + PathWide(heur.reason));
                                    }
                                }
                            }
                            if (!answered) {
                                FanotifyRespond(fanFd, efd, resp);
                                answered = true;
                            }
                            (void)answered;
                        }
                        ::close(efd);
                    }
                    if (ev->event_len == 0) break;
                    off += ev->event_len;
                }
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                int err = errno;
                Log(L"[实时防护] fanotify 读取出错（errno=" + std::to_wstring(err) +
                    L"），执行拦截停止，其余轮询继续");
                ::close(fanFd);
                fanFd = -1;
                m_driverLoaded = false;
            }
        }

        // 周期轮询：C2 连接 / 持久化项
        auto now = std::chrono::steady_clock::now();
        if (now - lastPoll >= std::chrono::seconds(5)) {
            didWork = true;
            lastPoll = now;
            if (m_settings.networkProtect)  PollNetworkConnections();
            if (m_settings.scheduleProtect) PollScheduledTasks();
        }

        if (!didWork)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (fanFd >= 0) ::close(fanFd);
    m_driverLoaded = false;
}

// 驱动消息线程的 Linux 对应物：周期向 GUI 推送统计（Windows 由驱动事件触发）
void ProtectionService::DriverMessageThreadProc()
{
    while (m_running.load()) {
        ServiceCallbacks cb;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            cb = m_callbacks;
        }
        Stats s = GetStats();
        if (cb.onStats) cb.onStats(s);
        for (int i = 0; i < 20 && m_running.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// ===========================================================================
// 事件与威胁处置
// ===========================================================================
void ProtectionService::HandleEvent(const yx::Event& ev)
{
    auto hit = m_rules.Evaluate(ev);
    if (!hit) return;
    HandleThreat(*hit);
}

void ProtectionService::HandleThreat(const yx::RuleHit& hit)
{
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_stats.ThreatsDetected++;
        if (hit.category == RuleCategory::YinHuC2 ||
            hit.category == RuleCategory::YinHuDllSideLoad ||
            hit.category == RuleCategory::YinHuProcessInject ||
            hit.category == RuleCategory::YinHuTaskPersist ||
            hit.category == RuleCategory::YinHuByovd) {
            m_stats.YinHuDetected++;
        }
    }

    // 去重：同一目标 10 秒内不重复处置（轮询型检测会反复命中）
    std::wstring key = hit.object.empty() ? hit.subject : hit.object;
    {
        std::lock_guard<std::mutex> lk(m_threatMutex);
        ULONGLONG now = GetTickCount64();
        auto it = m_lastThreatByPath.find(key);
        if (it != m_lastThreatByPath.end() && now - it->second < 10000)
            return;
        m_lastThreatByPath[key] = now;
    }

    ServiceCallbacks cb;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        cb = m_callbacks;
    }
    if (cb.onToast)
        cb.onToast(ToastType::Critical, L"检测到威胁", hit.description);
    Log(L"[威胁] " + hit.description);

    // 处置方式：自动 = 设置值；手动 = GUI 弹窗决策
    int action = -1;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (m_settings.autoHandle)
            action = m_settings.autoAction;
    }

    if (action < 0) {
        if (!cb.onThreatDecision) {
            Log(L"[处置] 手动确认模式但 GUI 未提供决策回调，已放行: " + hit.description);
            return;
        }
        {
            std::lock_guard<std::mutex> lk(m_decisionMutex);
            m_pendingDecision = -1;
        }
        cb.onThreatDecision(hit, [this](int d) {
            {
                std::lock_guard<std::mutex> lk(m_decisionMutex);
                m_pendingDecision = d;
            }
            m_decisionCv.notify_all();
        });

        int d = ThreatDecision::Allow;
        {
            std::unique_lock<std::mutex> lk(m_decisionMutex);
            if (m_decisionCv.wait_for(lk, std::chrono::seconds(10),
                                      [this] { return m_pendingDecision >= 0; }))
                d = m_pendingDecision;
            m_pendingDecision = -1;
        }
        if (d == ThreatDecision::Allow) {
            Log(L"[处置] 用户选择放过: " + hit.description);
            return;
        }
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            action = m_settings.autoAction;
        }
    }

    ExecuteThreatAction(hit, action);
}

bool ProtectionService::ExecuteThreatAction(const yx::RuleHit& hit, int action)
{
    // action: 0=隔离, 1=删除, 2=放过
    if (action == 2) {
        Log(L"[处置] 用户选择放过: " + hit.description);
        return true;
    }

    // 客体是受保护的系统资源：只记录，绝不动系统文件（Linux 上误删代价极高）
    if (hit.protectedObject) {
        Log(L"[处置] 已拦截对受保护资源的修改，仅记录（Linux 不自动删除系统文件）: " +
            hit.description);
        return true;
    }

    // 持久化项（cron/systemd 条目）：只上报，不自动删除条目文件——
    // 条目文件往往属于系统或用户其它任务，删除整个文件会误伤
    if (hit.category == RuleCategory::YinHuTaskPersist) {
        Log(L"[处置] 请人工确认并清理持久化项: " +
            (hit.object.empty() ? hit.description : hit.object));
        return true;
    }

    std::wstring path = hit.subject.empty() ? hit.object : hit.subject;
    if (path.empty()) {
        Log(L"[处置] 无关联文件，仅记录: " + hit.description);
        return true;
    }

    // 目标若正在运行，先终止进程再处置文件
    DWORD pid = FindPidByExePath(path);
    if (pid != 0 && pid != GetSelfPid()) {
        if (KillProcessByPid(pid))
            Log(L"[处置] 已终止进程 pid=" + std::to_wstring(pid) + L": " + path);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (action == 0)
        return ForceQuarantineFile(path);
    return ForceDeleteFile(path);
}

// ===========================================================================
// 隔离区
// ===========================================================================
void ProtectionService::EnsureQuarantineDir()
{
    std::error_code ec;
    if (m_quarantineDir.empty())
        m_quarantineDir = PathWide(DataDirPath() + "/Quarantine");
    fs::create_directories(m_quarantineDir, ec);
}

bool ProtectionService::QuarantineFile(const std::wstring& path)
{
    EnsureQuarantineDir();
    std::error_code ec;
    if (!fs::exists(path, ec)) return false;

    std::wstring name = fs::path(path).filename().wstring();
    std::wstring dest = m_quarantineDir + L"/" + name;
    if (!HasQuarSuffix(dest)) dest += kQuarSuffix;

    if (fs::exists(dest, ec)) {
        ec.clear();
        // 同名已存在：加时间戳避免覆盖
        dest = m_quarantineDir + L"/" + name + L"." +
               std::to_wstring((long long)::time(nullptr)) + kQuarSuffix;
    }

    fs::rename(path, dest, ec);   // 跨设备（如 /tmp -> HOME）会失败，回退复制
    if (ec) {
        ec.clear();
        fs::copy_file(path, dest, fs::copy_options::overwrite_existing, ec);
        if (!ec) {
            std::error_code ec2;
            fs::remove(path, ec2);
        }
    }
    if (ec) {
        Log(L"[隔离] 失败: " + path + L"（" + PathWide(ec.message()) + L"）");
        return false;
    }

    WriteQuarantineMeta(dest, path);
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_stats.FilesQuarantined++;
    }
    Log(L"[隔离] 已隔离: " + path);
    return true;
}

bool ProtectionService::RestoreFile(const std::wstring& path)
{
    EnsureQuarantineDir();

    std::wstring rawName = fs::path(path).filename().wstring();
    if (rawName.empty()) return false;

    // 兼容：传入完整路径 / 文件名 / 去后缀名
    std::wstring qfile = m_quarantineDir + L"/" + rawName;
    std::error_code ec;
    if (!fs::exists(qfile, ec)) {
        ec.clear();
        std::wstring want = StripQuarSuffixes(rawName);
        bool found = false;
        for (fs::directory_iterator it(m_quarantineDir, ec); !ec && it != fs::directory_iterator();
             it.increment(ec)) {
            std::wstring n = it->path().filename().wstring();
            if (n == rawName || StripQuarSuffixes(n) == want) {
                qfile = it->path().wstring();
                found = true;
                break;
            }
        }
        if (!found) {
            Log(L"[恢复] 隔离区中未找到: " + rawName);
            return false;
        }
    }

    std::wstring orig;
    if (!ReadQuarantineMeta(qfile, orig) || orig.empty()) {
        // 无元数据：退回可执行文件目录（与 Windows 版一致的兜底）
        std::wstring base = StripQuarSuffixes(fs::path(qfile).filename().wstring());
        orig = (fs::path(ExeDirW()) / base.c_str()).wstring();
    }

    std::error_code ec2;
    fs::create_directories(fs::path(orig).parent_path(), ec2);
    ec2.clear();

    fs::rename(qfile, orig, ec2);
    if (ec2) {
        ec2.clear();
        fs::copy_file(qfile, orig, fs::copy_options::overwrite_existing, ec2);
        if (!ec2) {
            std::error_code ec3;
            fs::remove(qfile, ec3);
        }
    }
    if (ec2) {
        Log(L"[恢复] 失败: " + qfile + L" -> " + orig + L"（" + PathWide(ec2.message()) + L"）");
        return false;
    }

    std::error_code ec4;
    fs::remove(MetaPathOf(qfile), ec4);
    Log(L"[恢复] 已还原: " + orig);
    return true;
}

// ===========================================================================
// 强制操作（对应 Windows 的驱动 IOCTL 强制接口）
// ===========================================================================
bool ProtectionService::KillProcessByPid(DWORD pid)
{
    if (pid == 0 || pid == GetSelfPid()) return false;
    if (::kill((pid_t)pid, SIGKILL) != 0)
        return errno == ESRCH;   // 进程已退出视为成功
    return true;
}

bool ProtectionService::ForceDeleteFile(const std::wstring& path)
{
    std::error_code ec;
    if (!fs::exists(path, ec)) return false;

    DWORD pid = FindPidByExePath(path);
    if (pid != 0 && pid != GetSelfPid()) KillProcessByPid(pid);

    if (!fs::remove(path, ec)) {
        Log(L"[处置] 删除失败: " + path + L"（" + PathWide(ec.message()) + L"）");
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_stats.FilesBlocked++;
    }
    Log(L"[处置] 已删除: " + path);
    return true;
}

bool ProtectionService::ForceQuarantineFile(const std::wstring& path)
{
    DWORD pid = FindPidByExePath(path);
    if (pid != 0 && pid != GetSelfPid()) KillProcessByPid(pid);
    return QuarantineFile(path);
}

DWORD ProtectionService::FindProcessByPath(const std::wstring& path)
{
    return FindPidByExePath(path);
}

bool ProtectionService::IsMicrosoftSignedCached(const std::wstring& dosPath)
{
    (void)dosPath;
    // Linux 无 Authenticode 签名体系：一律视为"未签名"，参与完整扫描
    static std::once_flag once;
    std::call_once(once, [this] {
        Log(L"[签名] Linux 无微软签名验证，所有文件均参与扫描");
    });
    return false;
}

// ===========================================================================
// 设置与持久化
// ===========================================================================
bool ProtectionService::ApplySettings(const ProtectSettings& s)
{
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_settings = s;
    }
    Log(L"[设置] 防护配置已更新（文件:" + std::wstring(s.fileProtect ? L"开" : L"关") +
        L" 进程:" + std::wstring(s.processProtect ? L"开" : L"关") +
        L" 网络:" + std::wstring(s.networkProtect ? L"开" : L"关") +
        L" 持久化:" + std::wstring(s.scheduleProtect ? L"开" : L"关") + L"）");
    SaveSettingsToFile();
    return true;
}

ProtectSettings ProtectionService::GetProtectSettings() const
{
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_settings;
}

bool ProtectionService::SaveSettingsToFile()
{
    ProtectSettings s = GetProtectSettings();
    std::ofstream f(PathNarrow(ConfigFilePathW()), std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        Log(L"[设置] 配置保存失败: " + ConfigFilePathW());
        return false;
    }
    auto b = [](bool v) { return v ? "true" : "false"; };
    f << "fileProtect="      << b(s.fileProtect)      << "\n"
      << "processProtect="   << b(s.processProtect)   << "\n"
      << "registryProtect="  << b(s.registryProtect)  << "\n"
      << "scheduleProtect="  << b(s.scheduleProtect)  << "\n"
      << "networkProtect="   << b(s.networkProtect)   << "\n"
      << "injectProtect="    << b(s.injectProtect)    << "\n"
      << "yinHuProtect="     << b(s.yinHuProtect)     << "\n"
      << "selfProtect="      << b(s.selfProtect)      << "\n"
      << "mbrProtect="       << b(s.mbrProtect)       << "\n"
      << "autoHandle="       << b(s.autoHandle)       << "\n"
      << "autoAction="       << s.autoAction          << "\n"
      << "processStartScan=" << b(s.processStartScan) << "\n";
    return true;
}

bool ProtectionService::LoadSettingsFromFile()
{
    std::ifstream f(PathNarrow(ConfigFilePathW()), std::ios::binary);
    if (!f.is_open()) return false;

    ProtectSettings s = GetProtectSettings();
    std::string line;
    auto asBool = [](const std::string& v) { return v == "true" || v == "1"; };
    while (std::getline(f, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        if      (k == "fileProtect")      s.fileProtect = asBool(v);
        else if (k == "processProtect")   s.processProtect = asBool(v);
        else if (k == "registryProtect")  s.registryProtect = asBool(v);
        else if (k == "scheduleProtect")  s.scheduleProtect = asBool(v);
        else if (k == "networkProtect")   s.networkProtect = asBool(v);
        else if (k == "injectProtect")    s.injectProtect = asBool(v);
        else if (k == "yinHuProtect")     s.yinHuProtect = asBool(v);
        else if (k == "selfProtect")      s.selfProtect = asBool(v);
        else if (k == "mbrProtect")       s.mbrProtect = asBool(v);
        else if (k == "autoHandle")       s.autoHandle = asBool(v);
        else if (k == "autoAction")       s.autoAction = ::atoi(v.c_str());
        else if (k == "processStartScan") s.processStartScan = asBool(v);
    }
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_settings = s;
    }
    return true;
}

// ===========================================================================
// 自我保护 / 统计 / 受保护路径
// ===========================================================================
bool ProtectionService::EnableSelfProtection()
{
    // Linux 无内核自保护：靠文件权限（隔离区 0700）+ 进程运行身份保护
    m_selfProtectOn = true;
    EnsureQuarantineDir();
    std::error_code ec;
    fs::permissions(m_quarantineDir,
                    fs::perms::owner_all,
                    fs::perm_options::replace, ec);
    Log(L"[自保护] 已启用用户级保护（隔离区权限收紧为 0700；Linux 无内核自保护）");
    return true;
}

bool ProtectionService::DisableSelfProtection()
{
    m_selfProtectOn = false;
    Log(L"[自保护] 已关闭");
    return true;
}

bool ProtectionService::SendProtectPaths()
{
    EnsureQuarantineDir();
    return true;
}

yx::Stats ProtectionService::GetStats() const
{
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_stats;
}

// ===========================================================================
// 驱动相关：Linux 无内核驱动，给出安全降级
// ===========================================================================
bool ProtectionService::OpenDriver() { return false; }
void ProtectionService::CloseDriver() {}
bool ProtectionService::ConnectFilterPort() { return false; }
bool ProtectionService::SendProtectFlags() { return false; }
bool ProtectionService::InstallAndStartDriver() { return false; }
std::wstring ProtectionService::LocateDriverFile() { return L""; }

void ProtectionService::OnDriverEvent(const YX_EVENT& ev)
{
    (void)ev;   // Linux 无驱动事件
}

bool ProtectionService::SetDriverStartType(DriverStartType type, std::wstring& errMsg)
{
    // Linux 映射："驱动启动类型" -> systemd 用户单元的开机自启开关。
    // 单元文件缺失时根据当前可执行文件路径自动生成。
    const char* x = ::getenv("XDG_CONFIG_HOME");
    std::string cfgBase = (x && *x) ? x : (HomeDir() + "/.config");
    std::string unitDir = cfgBase + "/systemd/user";
    std::string unitFile = unitDir + "/banjiu-guard.service";

    std::error_code ec;
    fs::create_directories(unitDir, ec);

    if (type != DriverStart_Disabled) {
        wchar_t exeBuf[4096] = { 0 };
        yx::GetModuleFileNameW(nullptr, exeBuf, 4095);
        std::string exe = PathNarrow(exeBuf);
        if (exe.empty()) {
            errMsg = L"无法获取可执行文件路径，无法生成 systemd 单元";
            return false;
        }
        std::ofstream f(unitFile, std::ios::trunc);
        if (!f.is_open()) {
            errMsg = L"无法写入 " + PathWide(unitFile);
            return false;
        }
        f << "[Unit]\n"
          << "Description=BanJiu-Guard real-time protection (fanotify)\n"
          << "After=graphical-session.target\n"
          << "PartOf=graphical-session.target\n\n"
          << "[Service]\n"
          << "Type=simple\n"
          << "ExecStart=" << exe << " --autostart\n"
          << "Environment=DISPLAY=:0\n"
          << "Environment=WAYLAND_DISPLAY=wayland-0\n"
          << "Restart=on-failure\n"
          << "RestartSec=3\n\n"
          << "[Install]\n"
          << "WantedBy=default.target\n";
        f.close();
    }

    std::string cmd = std::string("systemctl --user ") +
        (type == DriverStart_Disabled ? "disable --now" : "enable --now") +
        " banjiu-guard.service 2>&1";

    FILE* p = ::popen(cmd.c_str(), "r");
    if (!p) {
        errMsg = L"无法执行 systemctl --user（errno=" + std::to_wstring(errno) + L"）";
        return false;
    }
    char buf[512];
    std::string out;
    while (::fgets(buf, sizeof(buf), p)) out += buf;
    int rc = ::pclose(p);

    if (rc == 0) {
        Log(L"[启动项] systemd 用户服务已" +
            std::wstring(type == DriverStart_Disabled ? L"禁用" : L"启用"));
        return true;
    }
    errMsg = L"systemctl --user 失败（单元已生成到 " + PathWide(unitFile) +
             L"，可手动执行：systemctl --user daemon-reload && "
             L"systemctl --user enable --now banjiu-guard）";
    if (!out.empty()) errMsg += L"\n" + PathWide(out);
    return false;
}

ProtectionService::DriverStartType ProtectionService::GetDriverStartType()
{
    FILE* p = ::popen("systemctl --user is-enabled banjiu-guard.service 2>/dev/null", "r");
    if (!p) return DriverStart_Demand;
    char buf[128] = { 0 };
    if (!::fgets(buf, sizeof(buf), p)) { ::pclose(p); return DriverStart_Demand; }
    ::pclose(p);
    std::string s(buf);
    if (s.rfind("enabled", 0) == 0) return DriverStart_Auto;
    if (s.rfind("disabled", 0) == 0) return DriverStart_Disabled;
    if (s.rfind("static", 0) == 0) return DriverStart_Demand;
    return DriverStart_Demand;
}

// ===========================================================================
// 轮询：网络 C2
// ===========================================================================
void ProtectionService::PollNetworkConnections()
{
    static const char* kFiles[] = { "/proc/net/tcp", "/proc/net/tcp6" };
    for (const char* fp : kFiles) {
        std::ifstream in(fp);
        if (!in.is_open()) continue;
        std::string line;
        std::getline(in, line);   // 表头
        while (std::getline(in, line)) {
            std::istringstream ss(line);
            std::string sl, local, rem, st;
            if (!(ss >> sl >> local >> rem >> st)) continue;
            if (st != "01") continue;              // 仅 ESTABLISHED
            std::string ip = HexAddrToIp(rem);
            if (ip.empty()) continue;
            std::wstring ipw = PathWide(ip);
            if (m_rules.IsYinHuC2(ipw)) {
                yx::Event e;
                e.type = 40;                        // YX_EVENT_NET_CONNECT
                e.timestamp = GetTickCount64();
                e.name2 = ipw;
                e.processPath = L"";
                HandleEvent(e);
            }
        }
    }
}

// ===========================================================================
// 轮询：持久化项（cron / systemd user unit / rc.local）
// ===========================================================================
void ProtectionService::PollScheduledTasks()
{
    static const char* kDirs[] = {
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly",
        "/var/spool/cron", "/var/spool/cron/crontabs",
        "/etc/systemd/system",
    };

    // 可疑内容特征：从临时目录执行、下载即执行
    auto looksMalicious = [](const std::string& content) {
        bool toSh = content.find("| sh") != std::string::npos ||
                    content.find("| bash") != std::string::npos;
        bool downloader = content.find("curl") != std::string::npos ||
                          content.find("wget") != std::string::npos;
        return content.find("/dev/shm/") != std::string::npos ||
               (downloader && toSh);
    };

    for (const char* dir : kDirs) {
        DIR* d = ::opendir(dir);
        if (!d) continue;
        while (struct dirent* e = ::readdir(d)) {
            if (e->d_name[0] == '.') continue;
            std::string full = std::string(dir) + "/" + e->d_name;
            struct stat st;
            if (::stat(full.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;

            std::wstring wname = PathWide(e->d_name);
            if (m_reportedTasks.count(wname)) continue;

            bool bad = m_rules.IsYinHuTaskName(wname);
            if (!bad) {
                std::ifstream f(full);
                if (f.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(f)),
                                        std::istreambuf_iterator<char>());
                    if (content.size() > 8192) content.resize(8192);
                    bad = looksMalicious(content);
                }
            }
            if (!bad) continue;

            m_reportedTasks.insert(wname);

            RuleHit hit;
            hit.category = RuleCategory::YinHuTaskPersist;
            hit.level = ThreatLevel::High;
            hit.object = PathWide(full);
            hit.subject = L"";
            hit.protectedObject = false;
            hit.description = L"检测到可疑持久化项（cron/systemd）: " + PathWide(full);
            HandleThreat(hit);
        }
        ::closedir(d);
    }
}

// ===========================================================================
// 进程自身 PID
// ===========================================================================
uint32_t GetSelfPid() { return (uint32_t)::getpid(); }

} // namespace yx
