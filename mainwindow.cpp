#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QTableWidget>
#include <QDateTime>
#include "pidropcap_cap_cap.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->pb,SIGNAL(clicked(bool)),this,SLOT(on_pushButton_clicked()));
    connect(ui->pb1,SIGNAL(clicked(bool)),this,SLOT(on_pb1_clicked()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    ui->listWidget->clear();
    QString path = ui->lineEdit->text();
    std::string pat = path.toStdString();
    gg.ReadPack(pat.c_str());
    for(int i = 0; i < gg.packets_head.size();i++)
    {
        char *dt = new char[6];
        memset(dt,0,6);
        char *dt1 = new char[10];
        memset(dt1,0,10);
        itoa(i + 1, dt1, 10);
        itoa(gg.packets_head.data()[i].caplen, dt, 10);
        QString t("Packet# ");
        t.push_back(dt1);
        t.push_back("; Length: ");
        t.push_back(dt);
        t.push_back("; ");
        t.push_back(gg.packets_body.data()[i].c_str());
        ui->listWidget->addItem(t);
        delete [] dt;
        delete [] dt1;
    }

}



void MainWindow::on_pb1_clicked()
{
    ui->listWidget->clear();
    QDateTime start = QDateTime::currentDateTime();
    gg.BubbleSortLen();
    QDateTime finish = QDateTime::currentDateTime();
    int secs = finish.secsTo(start);
    start.addSecs(secs);
    int msecs = finish.time().msecsTo(start.time());
    int msecs_duration = secs * 1000 + msecs;
    QString timealg = QString::number(msecs);
    //ui->label_2->setText(timealg);
    for(int k = 0; k < gg.packets_head.size(); k++)
    {
        char *dt = new char[6];
        memset(dt,0,6);
        char *dt1 = new char[10];
        memset(dt1,0,10);
        itoa(k + 1, dt1, 10);
        itoa(gg.packets_head.data()[k].caplen, dt, 10);
        QString t("Packet# ");
        t.push_back(dt1);
        t.push_back("; Length: ");
        t.push_back(dt);
        t.push_back("; ");
        t.push_back(gg.packets_body.data()[k].c_str());
        ui->listWidget->addItem(t);
        delete [] dt;
        delete [] dt1;
    }

}

void MainWindow::on_pb2_clicked()
{
    ui->listWidget->clear();
}
