cmake_minimum_required(VERSION 3.16)
project(BanJiu-Guard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# 构建选项
# ---------------------------------------------------------------------------
option(BANJIU_BUILD_GUI     "构建 Qt 图形界面" ON)
option(BANJIU_BUILD_SERVICE "构建实时防护（Windows：服务库 / Linux：守护进程）" ON)
option(BANJIU_WITH_ML       "启用 LightGBM 机器学习引擎（缺失时自动降级为纯启发式）" ON)

if(WIN32)
    # ---- 静态 Qt 路径（无 ICU，全静态；旧版 qt-static-msvc 含 ICU 依赖）----
    if(NOT DEFINED QT_STATIC_PREFIX)
        set(QT_STATIC_PREFIX "D:/program/qt-static-msvc-noicu")
    endif()
    set(CMAKE_PREFIX_PATH "${QT_STATIC_PREFIX}")

    # ---- 静态 CRT（与静态 Qt 匹配 /MT）----
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    # ---- MSVC 编译选项 ----
    if(MSVC)
        add_compile_options(/W3 /utf-8)
        add_compile_definitions(UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
    endif()

    # ---- 静态 Qt 必需宏 ----
    # QT_STATIC：标记静态构建（避免 __declspec(dllimport)）
    # QT_STATICPLUGIN：让 Q_IMPORT_PLUGIN 宏真正展开（否则宏为空，插件永远不导入）
    add_compile_definitions(QT_STATIC QT_STATICPLUGIN)
else()
    # ---- Linux / 跨平台 ----
    # 系统 Qt（动态链接），不定义 QT_STATIC/QT_STATICPLUGIN
    add_compile_options(-Wall -Wno-unused-parameter -Wno-missing-field-initializers)
    add_compile_definitions(NOMINMAX)
endif()

# ---------------------------------------------------------------------------
# 子工程（driver 为 Windows WDK 工程，使用 build_driver.bat 独立编译，不进 CMake）
# ---------------------------------------------------------------------------
add_subdirectory(src/common)

if(BANJIU_BUILD_SERVICE)
    add_subdirectory(src/service)
endif()

if(BANJIU_BUILD_GUI)
    add_subdirectory(src/gui)
endif()
