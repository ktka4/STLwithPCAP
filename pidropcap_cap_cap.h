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
    char bufferr[PCAP_ERRBUF_SIZE];// ���� �� ��砩 ������������� �訡�� �� ࠡ�� � pcap ������⥪��
    ip_header *ih; //㪠��⥫� �� �������� ip ���������
    const u_char *data; //��६����� ��� �࠭���� ����� �� .pcap 䠩��, �� ��� �㤥� �믨������ ���������
    int pcount = 0; //����稪 ����⮢
    struct pcap_pkthdr *header; // ��������� .pcap 䠩��, ᮤ�ন� �६� ��墠� ����� � ����� ���� � ��墠祭��� ������
    const struct ethernet_header *ethernet; /* 㪠��⥫� �� ��������� �஢�� ethernet */
    const struct ip_header *ip;   /* 㪠��⥫� �� ip ��������� */
    const struct tcp_header *tcp;   /* 㪠��⥫� �� TCP ��������� */
    char *pdata;     /* 㪠��⥫� �� ����� ������� �����*/
    int size_ethernet; // ࠧ���� ����������
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
        pcap = pcap_open_offline(path.c_str(), bufferr); // ���뢠�� ��� .pcap 䠩�



        size_ethernet = sizeof(struct ethernet_header); // ࠧ���� ����������
        size_ip = sizeof(struct ip_header);
        size_tcp = sizeof(struct tcp_header);

        // \/  ��稭��� ������ ��� ����⨪� � .pcap 䠩�� � ������� 横�� while
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






            /*ethernet = (struct ethernet_header*)(data); // �믨������ ethernet ���������
            ip = (struct ip_header*)(data + size_ethernet); // ᬥ頥� 㪠��⥫� �� ��砫� ip ��������� � ���ᨢ� ���� ����� � �믨������ ���
            tcp = (struct tcp_header*)(data + size_ethernet + size_ip); // ᬥ頥� 㪠��⥫� �� ��砫� tcp ��������� � ���ᨢ� ���� ����� � �믨������ ���
            pdata = (char*)(data + size_ethernet + size_ip + size_tcp);// ᬥ頥� 㪠��⥫� �� ��砫� ������ ��襣� ����� � ���ᨢ� ���� ����� � �믨������ ����� ��襣� �����



            cout << "Src IP: " << (unsigned int)ip->saddr.byte1 << "." << (unsigned int)ip->saddr.byte2 << "." << (unsigned int)ip->saddr.byte3 << "." << (unsigned int)ip->saddr.byte4 << endl
                << "Dest IP: " << (unsigned int)ip->daddr.byte1 << "." <<(unsigned int)ip->daddr.byte2 << "." << (unsigned int)ip->daddr.byte3 << "." << (unsigned int)ip->daddr.byte4;
            cout << endl << endl;

            int len = header->len - size_ip - size_tcp - size_ethernet; // ����塞 ����� ������� ������

            cout << "����� ����� TCP � ��⭠����筮� ����("<<len<<" ����):"  << endl << endl;

            for(int i = 0; i < len; i++)
            {										//�뢮��� ����� �����
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
