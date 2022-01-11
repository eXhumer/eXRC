cmake_minimum_required(VERSION 3.22)

project(
eXRC
    LANGUAGES CXX
    VERSION 1.0.0
)

configure_file(LibConfig.hxx.in LibConfig.hxx)
find_package(Qt6 COMPONENTS Core Gui Network NetworkAuth REQUIRED)

qt_wrap_cpp(
LIB_MOC
    Include/${PROJECT_NAME}/Reddit.hxx
)

add_library(
${PROJECT_NAME}
    ${LIB_MOC}
    Source/AuthorizationData.cxx
    Source/RedditService.cxx
)

target_link_libraries(
${PROJECT_NAME}
    PUBLIC
        Qt6::Core
        Qt6::Gui
        Qt6::Network
        Qt6::NetworkAuth
)

target_include_directories(
${PROJECT_NAME}
    PRIVATE
        Include/${PROJECT_NAME}/
        PrivateInclude/
        ${CMAKE_CURRENT_BINARY_DIR}

    PUBLIC
        Include/
)
