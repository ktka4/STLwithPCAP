#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <pcap.h>
#include "structures.h"
#include "pidropcap_cap_cap.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public slots:
    void on_pushButton_clicked();

private slots:
    void on_pb1_clicked();

    void on_pb2_clicked();

private:
    Ui::MainWindow *ui;
public:
    PidroPcap_Cap_Cap gg;

};

#endif // MAINWINDOW_H
