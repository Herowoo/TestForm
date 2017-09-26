// WSBDLL.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "MyCode.h"
#include <WinSock2.h>
#include "iostream"
#pragma comment(lib,"ws2_32.lib")

//typedef struct tagCustomerInfo
//{
//	long CardClass;		//�����ͣ�4-M1����8-CPU��
//	long CustomerID;	//�˺����
//	long CardSN;		//���˳ֿ����
//	long Status;		//��״̬ F1H=���� F3H=��ʧ
//	long SubType;		//�����
//	long Ye;			//���	��λ����
//	long OpCount;		//���Ѽ���
//	char Name[32];		//����  
//	char ValidDate[12];	//��Ч���ڣ�YYYY-MM-DD
//	char CardASN[24];	//��Ӧ�����к�
//}CUSTOMERINFO;//�û���Ϣ�ṹ
typedef long(WINAPI *opCom)();
typedef long(WINAPI *querycard)(long*);				//Ѱ��
typedef long(WINAPI *getcardinfo)(CUSTOMERINFO*);	//��ȡ�û���Ϣ
/*
	�˷���������ȡ��Ƭ�ĺ�����״̬
	��ڲ�����	
		ip			socket��������ַ
		port		socket�������˿�
		asn			��Ƭasn
	���ڲ�����
		recv_buf	�����������ַ�
	����ֵ��
		-1			WSA����ʧ��
		-2			socket failed
		-3			socket����ʧ��
		-4			���������������ʧ��
		0			�ɹ�
*/
long GetBlackList(const char *ip, short port, char *asn, char *recv_buf)
{
	const int BUF_SIZE = 64;
	WSADATA         wsd;            //WSADATA����  
	SOCKET          sHost;          //�������׽���  
	SOCKADDR_IN     servAddr;       //��������ַ  
	char            buf[BUF_SIZE];  //�������ݻ�����  
	//char            bufRecv[BUF_SIZE];
	int             retVal;         //����ֵ  
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		return -1;		//WSA����ʧ��
	}
	sHost = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == sHost)
	{
		WSACleanup();
		return -2;		//socket failed
	}
	//�������׽��ֵ�ַ
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(port);
	servAddr.sin_addr.s_addr = inet_addr(ip);

	//���ӷ�����
	retVal = connect(sHost, (LPSOCKADDR)&servAddr, sizeof(servAddr));
	if (SOCKET_ERROR == retVal)
	{
		closesocket(sHost);
		WSACleanup();
		return -3;		//����ʧ��
	}
	//���������������
	ZeroMemory(buf, BUF_SIZE);
	strcpy_s(buf, asn);
	//strcpy(buf, asn);	//����ȫ
	retVal = send(sHost, buf, strlen(buf), 0);
	if (SOCKET_ERROR == retVal)
	{
		closesocket(sHost);
		WSACleanup();
		return -4;		//����ʧ��
	}
	char* recvbuf = recv_buf;
	recv(sHost, recvbuf, 1, 0);
	closesocket(sHost); //�ر��׽���  
	WSACleanup();       //�ͷ��׽�����Դ  
	return  0;
}
//������
long OpenCom()
{
	HMODULE hdllInst = LoadLibrary("Cap_RW.dll");
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		opCom opencom = (opCom)GetProcAddress(hdllInst, "OpenCom");
		if (opencom==NULL)
		{
			return -1701;
		}
		else
		{
			long status_opencom = opencom();
			return status_opencom;
		}
	}
}

//��ȡ�û���Ϣ
long CapGetNBCardInfo(CUSTOMERINFO *info)
{
	HMODULE hdllInst = LoadLibrary("Cap_RW.dll");
	if (hdllInst==NULL)
	{
		return -1801;
	}
	else
	{
		getcardinfo GetCardInfo;
		GetCardInfo = (getcardinfo)GetProcAddress(hdllInst, "CapGetNBCardInfo");
		if (GetCardInfo==NULL)
		{
			return -1701;
		}
		else
		{
			CUSTOMERINFO ctm_info;
			long status_getinfo = GetCardInfo(&ctm_info);
			const char* ipaddr = "192.168.10.65";
			short port = 8000;
			char* asn = ctm_info.CardASN;
			char recv_buf = '9';
			long status = GetBlackList(ipaddr, port, asn, &recv_buf);

			if (recv_buf=='0')
			{
				return 463;
			}
			else
			{
				return status_getinfo;
			}
			
		}
	}
}
//Ѱ��
long CapNBQueryCard(long *UID)
{
	HMODULE  hdllInst = LoadLibrary("Cap_RW.dll");
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		querycard QueryCard;

		QueryCard = (querycard)GetProcAddress(hdllInst, "CapNBQueryCard");
		if (QueryCard == NULL)
		{

			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			long uid;
			long query_status = QueryCard(&uid);
			return query_status;
		}
	}
}
