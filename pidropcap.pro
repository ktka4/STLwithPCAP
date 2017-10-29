#-------------------------------------------------
#
# Project created by QtCreator 2017-10-26T21:16:49
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = pidropcap
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    pidropcap_cap_cap.cpp

HEADERS  += mainwindow.h \
    pidropcap_cap_cap.h \
    structures.h

FORMS    += mainwindow.ui


INCLUDEPATH += C:/WpdPack/WpdPack/Include

LIBS += "-LC:/WpdPack/WpdPack/Lib" -lwpcap -lws2_32


DEFINES += WPCAP

DEFINES += HAVE_REMOTE

