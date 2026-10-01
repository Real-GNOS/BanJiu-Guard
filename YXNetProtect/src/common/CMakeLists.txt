# 公共库：特征库 + 规则引擎 + 启发式引擎 + ML 引擎（用户态）
# 规则/特征库为纯标准 C++；启发式与 ML 的 PE 解析在 Linux 上由 pe_image.h 提供等价结构。
add_library(yx_common STATIC
    yx_rules.cpp
    yx_heuristic.cpp
    yx_ml_engine.cpp
)

target_include_directories(yx_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ---------------------------------------------------------------------------
# LightGBM 机器学习引擎（可选）
#  - Windows：沿用 third_party/LightGBM 预编译静态库（build_lightgbm.bat 产物）
#  - Linux  ：优先使用 third_party/LightGBM 源码构建产物，缺失则自动降级
# ---------------------------------------------------------------------------
set(LIGHTGBM_SRC_DIR ${CMAKE_SOURCE_DIR}/third_party/LightGBM)

if(BANJIU_WITH_ML AND EXISTS ${LIGHTGBM_SRC_DIR}/include/LightGBM/c_api.h)
    target_include_directories(yx_common PUBLIC ${LIGHTGBM_SRC_DIR}/include)
    target_compile_definitions(yx_common PUBLIC BANJIU_ML_ENABLED LIGHTGBM_STATIC_LIB)

    if(WIN32)
        # Windows：预编译静态库（/MT）
        target_link_libraries(yx_common PUBLIC ${LIGHTGBM_SRC_DIR}/lib_lightgbm.lib)
    else()
        # Linux：链接源码构建产物（lib_lightgbm.a / .so），存在即启用
        file(GLOB LIGHTGBM_LIB
            ${LIGHTGBM_SRC_DIR}/lib_lightgbm.a
            ${LIGHTGBM_SRC_DIR}/lib_lightgbm.so
            ${LIGHTGBM_SRC_DIR}/build/lib_lightgbm.a
            ${LIGHTGBM_SRC_DIR}/build/lib_lightgbm.so)
        if(LIGHTGBM_LIB)
            target_link_libraries(yx_common PUBLIC ${LIGHTGBM_LIB})
            # 静态库依赖线程库
            find_package(Threads REQUIRED)
            target_link_libraries(yx_common PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
        else()
            # 头文件在但产物未编译：不定义 BANJIU_ML_ENABLED，引擎自动降级
            message(WARNING "BanJiu-Guard: 找到 LightGBM 头文件但缺少构建产物（third_party/LightGBM/build/），ML 引擎降级为不可用")
        endif()
    endif()
else()
    message(STATUS "BanJiu-Guard: ML 引擎已禁用（BANJIU_WITH_ML=OFF 或缺少 third_party/LightGBM），检测将退化为纯启发式")
endif()
