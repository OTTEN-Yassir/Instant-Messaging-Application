cmake_minimum_required(VERSION 3.0.0)
project(MessagerieClient VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()

file(GLOB QTView_headers
    "view/QTView/*.h"
)

qt_add_executable(MessagerieClient
    view/QTView/mainwindow.ui
    model/core.h model/crypto.h model/message.h
    view/view.h ${QTView_headers}
    src/model.cpp src/crypto.cpp src/QTView.cpp utils/subject.cpp main.cpp
)

target_link_libraries(MessagerieClient PRIVATE 
    Qt::Core
    Qt::Gui
    Qt::Widgets
    rnp
)
