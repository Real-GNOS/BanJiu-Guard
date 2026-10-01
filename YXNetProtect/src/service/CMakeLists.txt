# 实时防护服务（静态库，与 GUI 链接为同一可执行文件）
#
# Windows：内核 Minifilter 通信 + SCM 服务逻辑（yx_service.cpp / yx_first_run.cpp）
# Linux  ：fanotify 执行拦截 + 轮询检测的用户态实现
#          （linux/yx_service_linux.cpp / linux/yx_first_run_linux.cpp）

if(WIN32)
    set(SERVICE_SOURCES
        yx_service.cpp
        yx_first_run.cpp
    )
else()
    set(SERVICE_SOURCES
        linux/yx_service_linux.cpp
        linux/yx_first_run_linux.cpp
    )
endif()

add_library(yx_service STATIC ${SERVICE_SOURCES})

target_include_directories(yx_service PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(yx_service
    PUBLIC yx_common
)

find_package(Threads REQUIRED)
target_link_libraries(yx_service PUBLIC Threads::Threads)

if(NOT WIN32)
    # fanotify / /proc 解析使用 POSIX 接口；不需要额外库
    target_compile_options(yx_service PRIVATE -Wno-unused-parameter)
endif()
