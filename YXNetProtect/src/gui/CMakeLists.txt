cmake_minimum_required(VERSION 3.16)

# Qt GUI 可执行文件（Windows 与 Linux 共用同一套源码）
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

set(GUI_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    toast.cpp
    toast.h
    pages/dashboardpage.cpp
    pages/dashboardpage.h
    pages/scanpage.cpp
    pages/scanpage.h
    pages/quarantinepage.cpp
    pages/quarantinepage.h
    pages/logpage.cpp
    pages/logpage.h
    pages/settingspage.cpp
    pages/settingspage.h
    pages/aboutpage.cpp
    pages/aboutpage.h
)

if(WIN32)
    # 资源脚本（图标 + requireAdministrator 清单）仅 Windows 需要
    list(APPEND GUI_SOURCES app.rc)
endif()

add_executable(BanJiuGuard WIN32
    ${GUI_SOURCES}
    resources.qrc
)

target_include_directories(BanJiuGuard PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(BanJiuGuard PRIVATE
    Qt6::Widgets
    yx_service
    yx_common
)

if(WIN32)
    # ---- LightGBM 静态机器学习库（/MT 预编译，无 OpenMP 动态依赖）----
    set(LIGHTGBM_LIB ${CMAKE_SOURCE_DIR}/third_party/LightGBM/lib_lightgbm.lib)
    target_link_libraries(BanJiuGuard PRIVATE
        shell32
        dbghelp
        ${LIGHTGBM_LIB}
    )

    # 静态 Qt 必须显式导入静态插件，并用 WHOLE_ARCHIVE 强制链接所有符号
    # （否则 MSVC 链接器会丢弃未直接引用的插件注册函数，报 "no Qt platform plugin"）
    target_link_libraries(BanJiuGuard PRIVATE
        $<LINK_LIBRARY:WHOLE_ARCHIVE,Qt6::QWindowsIntegrationPlugin>
        $<LINK_LIBRARY:WHOLE_ARCHIVE,Qt6::QICOPlugin>
    )
endif()

# 部署 LightGBM 模型权重到 exe 同目录的 models/
set(ML_MODEL ${CMAKE_SOURCE_DIR}/models/lgbm_detector.txt)
add_custom_command(TARGET BanJiuGuard POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:BanJiuGuard>/models"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${ML_MODEL} "$<TARGET_FILE_DIR:BanJiuGuard>/models/lgbm_detector.txt"
    COMMENT "Deploying LightGBM model to models/lgbm_detector.txt"
)

set_target_properties(BanJiuGuard PROPERTIES
    OUTPUT_NAME "BanJiu-Guard"
)

if(WIN32)
    set_target_properties(BanJiuGuard PROPERTIES
        WIN32_EXECUTABLE TRUE
        # 强制要求管理员权限运行（UAC 提权），非管理员直接无法启动
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
else()
    # ---- Linux：运行时定位 lib_lightgbm.so（构建树或 exe 同目录）----
    set_target_properties(BanJiuGuard PROPERTIES
        BUILD_RPATH "$ORIGIN;${CMAKE_SOURCE_DIR}/third_party/LightGBM"
        INSTALL_RPATH "$ORIGIN"
    )
    # 把 lib_lightgbm.so 复制到输出目录，便于直接运行与打包分发
    file(GLOB LIGHTGBM_SO ${CMAKE_SOURCE_DIR}/third_party/LightGBM/lib_lightgbm.so)
    if(LIGHTGBM_SO)
        add_custom_command(TARGET BanJiuGuard POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${LIGHTGBM_SO} "$<TARGET_FILE_DIR:BanJiuGuard>"
            COMMENT "Deploying lib_lightgbm.so next to the executable"
        )
    endif()
endif()
