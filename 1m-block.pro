TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lnetfilter_queue

SOURCES += \
        main.cpp

HEADERS += \
    headers.h
