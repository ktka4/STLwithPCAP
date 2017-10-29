#ifndef PIDROPCAP_CAP_CAP_H
#define PIDROPCAP_CAP_CAP_H


#include <iostream>
#include <pcap.h>
#include <vector>
#include <string>
#include "structures.h"
#include "ui_mainwindow.h"


class PidroPcap_Cap_Cap
{
public:
    std::vector <pcap_pkthdr> packets_head;
    std::vector <std::string> packets_body;
    pcap_t * pcap;
    char bufferr[PCAP_ERRBUF_SIZE];// буфер на случай возникновения ошибки при работе с pcap библиотекой
    ip_header *ih; //указатель на структуру ip заголовка
    const u_char *data; //переменная для хранения пакета из .pcap файла, из неё будем выпиливать заголовки
    int pcount = 0; //счётчик пакетов
    struct pcap_pkthdr *header; // заголовок .pcap файла, содержит время захвата пакета и прочую инфу о захваченных пакетах
    const struct ethernet_header *ethernet; /* указатель на заголовок уровня ethernet */
    const struct ip_header *ip;   /* указатель на ip заголовок */
    const struct tcp_header *tcp;   /* указатель на TCP заголовок */
    char *pdata;     /* указатель на данные каждого пакета*/
    int size_ethernet; // размеры заголовков
    int size_ip;
    int size_tcp;
    int r;
    int ms;
public:
    PidroPcap_Cap_Cap();
    void ReadPack(std::string path)
    {
        pcount = 0;
        packets_body.clear();
        packets_head.clear();
        pcap = pcap_open_offline(path.c_str(), bufferr); // открываем наш .pcap файл



        size_ethernet = sizeof(struct ethernet_header); // размеры заголовков
        size_ip = sizeof(struct ip_header);
        size_tcp = sizeof(struct tcp_header);

        // \/  начинаем листать наши пакетики в .pcap файле с помощью цикла while
        while ((r = pcap_next_ex(pcap, &header, &data)) >= 0)
        {


            ++pcount;
            packets_head.push_back(*header);

            ip = (struct ip_header*)(data + size_ethernet);

            std::string adip;
            adip.append("Src IP: ");
            adip += std::to_string((unsigned int)ip->saddr.byte1);
            adip.append(".");
            adip += std::to_string((unsigned int)ip->saddr.byte2);
            adip.append(".");
            adip += std::to_string((unsigned int)ip->saddr.byte3);
            adip.append(".");
            adip += std::to_string((unsigned int)ip->saddr.byte4);
            adip.append("; ");
            adip.append("Dest IP: ");
            adip += std::to_string((unsigned int)ip->daddr.byte1);
            adip.append(".");
            adip += std::to_string((unsigned int)ip->daddr.byte2);
            adip.append(".");
            adip += std::to_string((unsigned int)ip->daddr.byte3);
            adip.append(".");
            adip += std::to_string((unsigned int)ip->daddr.byte4);

            packets_body.push_back(adip);






            /*ethernet = (struct ethernet_header*)(data); // выпиливаем ethernet заголовок
            ip = (struct ip_header*)(data + size_ethernet); // смещаем указатель на начало ip заголовка в массиве байт пакета и выпиливаем его
            tcp = (struct tcp_header*)(data + size_ethernet + size_ip); // смещаем указатель на начало tcp заголовка в массиве байт пакета и выпиливаем его
            pdata = (char*)(data + size_ethernet + size_ip + size_tcp);// смещаем указатель на начало данных нашего пакета в массиве байт пакета и выпиливаем данные нашего пакета



            cout << "Src IP: " << (unsigned int)ip->saddr.byte1 << "." << (unsigned int)ip->saddr.byte2 << "." << (unsigned int)ip->saddr.byte3 << "." << (unsigned int)ip->saddr.byte4 << endl
                << "Dest IP: " << (unsigned int)ip->daddr.byte1 << "." <<(unsigned int)ip->daddr.byte2 << "." << (unsigned int)ip->daddr.byte3 << "." << (unsigned int)ip->daddr.byte4;
            cout << endl << endl;

            int len = header->len - size_ip - size_tcp - size_ethernet; // вычисляем длину пакетных данных

            cout << "Данные пакета TCP в шестнадцатиричном виде("<<len<<" байт):"  << endl << endl;

            for(int i = 0; i < len; i++)
            {										//выводим данные пакета
                printf("%.2x ", pdata[i]);
            }




            cout << endl << endl;*/
        }
        pcap_close(pcap);

    };
    void BubbleSortLen()
    {
        for (int i = 0; i < packets_head.size(); ++i)
        {
            for (int j = packets_head.size()-1; j > i; --j)
            {
                if (packets_head.data()[i].caplen > packets_head.data()[j].caplen)
                {
                    swapV( packets_head[i], packets_head[j]);
                    swapV( packets_body[i], packets_body[j]);
                }
            }
        }
    };

QT_DECLARE_METATYPE(PidroPcap_Cap_Cap);
};


#endif // PIDROPCAP_CAP_CAP_H
