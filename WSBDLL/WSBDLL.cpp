// WSBDLL.cpp : ���� DLL Ӧ�ó���ĵ���������
//
#include <stdlib.h>
#include "stdafx.h"
#include "MyCode.h"
#include <WinSock2.h>
#include "iostream"
#pragma comment(lib,"ws2_32.lib")

//���������״̬,��ʼֵΪ0����֤�������Ϊ-1���Ǻ�����Ϊ1
int is_black = 0;
LPCSTR CONDLL = "Cap_RW.dll";
/*
�������ͨ�ӿں���
*/
//������
typedef long(WINAPI *opCom)();
//�ر�����
typedef void(WINAPI *closeCom)();
//Ѱ��
typedef long(WINAPI *querycard)(long*);
//��ȡ�û���Ϣ
typedef long(WINAPI *getcardinfo)(CUSTOMERINFO*);
//�ۿ�
typedef long(WINAPI *setcardinfo)(long, long, long, LPSTR, __int64*, long*, long*);
//5.6.	�ۿ�Ӵ�/���޶�ܣ�
typedef long(WINAPI *setcardinfoLMT)(long, long, long, LPSTR, long, long, __int64*, long*, long*);
//5.7.	�ۿ���޶����֤�������ѣ�
typedef long(WINAPI *setcardinfoVerify)(long, long, long, LPSTR, long, long, LPSTR, __int64*, long*, long*);
//5.8.	�������ۼ�����
typedef long(WINAPI *updatecardstatus)(long, LPSTR);
//5.9.	���¿���/���޶�
typedef long(WINAPI *setcardstatus)(long, long);
//5.10.	��������
typedef long(WINAPI *setcardPWD)(LPSTR, LPSTR);
//5.11.	��ֵ��ʼ��
typedef long(WINAPI *chargeInit)(long, long, __int64*, long*, long*, long*, long*);
//��ֵ
typedef long(WINAPI *capcharge)(LPSTR, LPSTR, LPSTR);
//5.12.	�ۿTAC�����ַ�����
typedef long(WINAPI *setcardinfo_str)(long, long, long, LPSTR, __int64*, long*, char*, int);
//5.13.	��ȡtacֵ
typedef long(WINAPI *gettac)(long, LPSTR);
//��ȡʮ�ν��׼�¼
typedef long(WINAPI *readrecords)(CONSUMEINFO*);

//�ۿ�,PSAM_IDʹ��LPSTR����
typedef long(WINAPI *setcardinfo_temp)(long, long, long, LPSTR, LPSTR, long*, char*, int);
/*
������񽡿����ӿں���
*/
//6.1.2	���豸
typedef HANDLE(WINAPI *opendevice)(int);
//6.1.3	�ر��豸
typedef int(WINAPI *closedevice)(HANDLE);
//6.1.4	�豸��λ
typedef int(WINAPI *poweron)(HANDLE, int, char*);
//6.1.5	����ָ��
typedef int(WINAPI *sendapdu)(HANDLE, unsigned char, unsigned char*, unsigned long, unsigned char*, int*);
//6.2.1	�������������������ļ��ӿ�
typedef int(WINAPI *r_ddf1ef05)(HANDLE, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*);
//6.2.2	���ֿ��˻�����Ϣ�����ļ��ӿ�
typedef int(WINAPI *r_ddf1ef06)(HANDLE, char*, char*, char*, char*, char*);
//����Ч�ڵ��ļ��ӿ�
typedef int(WINAPI *r_ddf1ef08)(HANDLE, char*, char*, char*, char*, char*, char*);
//д��Ч�ڵ��ļ��ӿ�
typedef int(WINAPI *w_ddf1ef08)(HANDLE, char*, char*, char*, char*, char*, char*);
//����ַ��Ϣ�ļ��ӿ�
typedef int(WINAPI *r_df01ef05)(HANDLE, char*, char*, char*, char*);
//д��ַ��Ϣ�ļ��ӿ�
typedef int(WINAPI *w_df01ef05)(HANDLE, char*, char*, char*, char*);
//����ϵ����Ϣ�ļ��ӿ�
typedef int(WINAPI *r_df01ef06)(HANDLE, char*, char*, char*, char*, char*, char*, char*, char*, char*);
//д��ϵ����Ϣ�ļ��ӿ�
typedef int(WINAPI *w_df01ef06)(HANDLE, char*, char*, char*, char*, char*, char*, char*, char*, char*);
//��ְҵ������Ϣ�ļ��ӿ�
typedef int(WINAPI *r_df01ef07)(HANDLE, char*, char*, char*);
//дְҵ������Ϣ�ļ��ӿ�
typedef int(WINAPI *w_df01ef07)(HANDLE, char*, char*, char*);
//��֤����¼��Ϣ�ļ��ӿ�
typedef int(WINAPI *r_df01ef08)(HANDLE, char*, char*, char*, char*);
//д֤����¼��Ϣ�ļ��ӿ�
typedef int(WINAPI *w_df01ef08)(HANDLE, char*, char*, char*, char*);
//���ٴ����������ļ��ӿ�
typedef int(WINAPI *r_df02ef05)(HANDLE, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*);
//д�ٴ����������ļ��ӿ�
typedef int(WINAPI *w_df02ef05)(HANDLE, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*);
//��������Ϣ�����ļ��ӿ�
typedef int(WINAPI *r_df02ef06)(HANDLE, char*);
//д������Ϣ�����ļ��ӿ�
typedef int(WINAPI *w_df02ef06)(HANDLE, char*);
//���������������ļ��ӿ�
typedef int(WINAPI *r_df02ef07)(HANDLE, int, char*, char*);
//д�������������ļ��ӿ�
typedef int(WINAPI *w_df02ef07)(HANDLE, char*, char*);
//�����߻��������ļ��ӿ�
typedef int(WINAPI *r_df02ef08)(HANDLE, int, char*, char*);
//д���߻��������ļ��ӿ�
typedef int(WINAPI *w_df02ef08)(HANDLE, char*, char*);
//��סԺ��Ϣ�����ļ��ӿ�
typedef int(WINAPI *r_df03ef05)(HANDLE, char*, char*, char*);
//дסԺ��Ϣ�����ļ��ӿ�
typedef int(WINAPI *w_df03ef05)(HANDLE, int);
//����סԺ��Ϣ�����ļ��ӿ�
typedef int(WINAPI *e_df03ef05)(HANDLE, int);
//��������Ϣ�����ļ��ӿ�
typedef int(WINAPI *r_df03ef06)(HANDLE, char*, char*, char*, char*, char*);
//д������Ϣ�����ļ��ӿ�
typedef int(WINAPI *w_df03ef06)(HANDLE, int);
//����������Ϣ�����ļ��ӿ�
typedef int(WINAPI *e_df03ef06)(HANDLE, int);
//��סԺ��Ϣ�ļ��ӿ�
typedef int(WINAPI *r_df03ee)(HANDLE, int, char*, int, int, int);
//дסԺ��Ϣ�ļ��ӿ�
typedef int(WINAPI *w_df03ee)(HANDLE, int, char*, int, int, int);
//����������Ϣ�ļ��ӿ�
typedef int(WINAPI *r_df03ed)(HANDLE, int, char*, int, int, int);
//д��������Ϣ�ļ��ӿ�
typedef int(WINAPI *w_df03ed)(HANDLE, int, char*, int, int, int);
//6.3.1	SM3ժҪ
typedef int(WINAPI *sm3)(HANDLE, BYTE*, int, BYTE*, BYTE*);
//6.3.2	PIN��֤����
typedef int(WINAPI *verifypin)(HANDLE, const char*, BYTE*);
//6.3.3	SM2ǩ������
typedef int(WINAPI *sm2)(HANDLE, BYTE*, BYTE, BYTE*, BYTE*);
//��ȡ�豸���к���Ϣ
typedef int(WINAPI *getcsn)(HANDLE, char*);
//��ȡSAM������Ϣ
typedef int(WINAPI *getsam)(HANDLE, char*);
//д�����������������ļ��ӿ�
typedef int(WINAPI *w_ddf1ef05)(HANDLE, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*);
//д�ֿ��˻�����Ϣ�����ļ��ӿ�
typedef int(WINAPI *w_ddf1ef06)(HANDLE, char*, char*, char*, char*, char*);
//����Ƭ�ļ��ӿ�
typedef int(WINAPI *r_df1ef07)(HANDLE, char*);
//д��Ƭ�ļ��ӿ�
typedef int(WINAPI *w_df1ef07)(HANDLE, char*);
//��ȡסԺ�����Žӿ�
typedef int(WINAPI *get_eeindex)(HANDLE);
//��ȡ���������Žӿ�
typedef int(WINAPI *get_edindex)(HANDLE);
//������Ա��Ϣ��ʼ��
typedef int(WINAPI *lockinfo)(HANDLE);

//����ҽԺ���ƽӿڣ����������������������
typedef int(WINAPI *getinfo_his)(HANDLE, char*, long*, char*, char*, char*, char*);

/*========================================ʵ�ֳ���ͨ�ӿ�=======================================================*/

/*
�˷���������ȡ��Ƭ�ĺ�����״̬
��ڲ�����
ip			socket��������ַ
port		socket�������˿�
uid			��Ƭuid
���ڲ�����
recv_buf	�����������ַ�
����ֵ��
-1			WSA����ʧ��
-2			socket failed
-3			socket����ʧ��
-4			���������������ʧ��
0			�ɹ�
*/
long _stdcall GetBlackList(const char *ip, short port, long uid, char *recv_buf)
{
	const int BUF_SIZE = 64;
	WSADATA         wsd;            //WSADATA����  
	SOCKET          sHost;          //�������׽���  
	SOCKADDR_IN     servAddr;       //��������ַ  
	char            buf[BUF_SIZE];  //�������ݻ�����  
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
	itoa(uid, buf, 10);
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

//��ȡ��������֤���ӳ�ʱʱ�����ƣ�
long _stdcall GetBlack_limit(const char *ip, short port, long uid, char *recv_buf)
{
	const int BUF_SIZE = 64;
	WSADATA         wsd;            //WSADATA����  
	SOCKET          sHost;          //�������׽���  
	SOCKADDR_IN     servAddr;       //��������ַ  
	char            buf[BUF_SIZE];  //�������ݻ�����  
	timeval			tm;
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
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(port);
	servAddr.sin_addr.s_addr = inet_addr(ip);

	//���ó�ʱʱ��
	fd_set set;
	int error = -1;
	int len = sizeof(int);
	unsigned long ul = 1;
	ioctlsocket(sHost, FIONBIO, &ul); //����Ϊ������ģʽ
	bool ret = false;
	if (connect(sHost, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1)
	{
		tm.tv_sec = 5;	//��ʱʱ�䣬��λ��
		tm.tv_usec = 0;
		FD_ZERO(&set);
		FD_SET(sHost, &set);
		if (select(sHost + 1, NULL, &set, NULL, &tm) > 0)
		{
			getsockopt(sHost, SOL_SOCKET, SO_ERROR, (char *)&error, &len);
			if (error == 0)
			{
				ret = true;
			}
			else
			{
				ret = false;
			}
		}
		else
		{
			ret = false;
		}
	}
	else
	{
		ret = true;
	}
	ul = 0;
	ioctlsocket(sHost, FIONBIO, &ul);
	if (!ret)
	{
		closesocket(sHost);
		return -101;
	}
	else
	{
		//���������������
		ZeroMemory(buf, BUF_SIZE);
		itoa(uid, buf, 10);
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
}
//����POST����
long _stdcall SendPostRequest(const char *ip, short port, long uid, char *recv_buf)
{
	const int BUF_SIZE = 64;
	WSADATA         wsd;            //WSADATA����  
	SOCKET          sHost;          //�������׽���  
	SOCKADDR_IN     servAddr;       //��������ַ  
	char            buf[BUF_SIZE];  //�������ݻ�����  
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
	itoa(uid, buf, 10);
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

//��ȡ�����ļ�IP��ַ
LPSTR _stdcall GetIPAddrINI()
{
	LPSTR LP_PATH = new char[MAX_PATH];
	LPSTR ipaddr = new char[20];
	strcpy(LP_PATH, "./ChgCity.ini");
	GetPrivateProfileStringA("SERVER", "IPADDR", "NULL", ipaddr, 20, LP_PATH);
	delete[] LP_PATH;
	return ipaddr;
}
//��ȡ�����ļ�port
short  GetPortINI()
{
	LPSTR LP_PATH = new char[MAX_PATH];
	strcpy(LP_PATH, "./ChgCity.ini");
	short port;
	port = GetPrivateProfileIntA("SERVER", "PORT", -1, LP_PATH);
	delete[] LP_PATH;
	return port;
}
//ͨ��UID��֤������
long VerifiBlackCard_UID(long u_id)
{
	const char* ipaddr = GetIPAddrINI();
	short port = GetPortINI();
	char recv_buf = '9';
	long status = GetBlackList(ipaddr, port, u_id, &recv_buf);
	if (status == 0)
	{
		//socket����ֵΪ1����ʾ�˿�UID�ں���������
		if (recv_buf == '1')
		{
			is_black = -1;
			return 463;
		}
		//socket����ֵΪ2����ʾ�ӿڷ����쳣������������
		if (recv_buf == '2')
		{
			int i = 0;
			int max_count = 10;
			while ((recv_buf == '2') && (i < max_count))
			{
				GetBlackList(ipaddr, port, u_id, &recv_buf);
				i++;
			}
			switch (recv_buf)
			{
			case '2':
				is_black = 0;
				return 404;
				break;
			case '1':
				is_black = -1;
				return 463;
				break;
			case '0':
				is_black = 1;
				return 0;
				break;
			default:
				return 51;
				break;
			}
		}
		else
		{
			is_black = 1;
			return 0;
		}
	}

	else
	{
		return 404;					//��������֤�ӿ������쳣
	}
}
//������
long _stdcall OpenCom()
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		opCom opencom = (opCom)GetProcAddress(hdllInst, "OpenCom");
		if (opencom == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			long status_opencom = opencom();
			FreeLibrary(hdllInst);
			return status_opencom;
		}
	}
}
//�ر�����
void  CloseCom()
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	closeCom c_com = (closeCom)GetProcAddress(hdllInst, "CloseCom");
	c_com();
	FreeLibrary(hdllInst);
}
//��ȡ�û���Ϣ
long _stdcall  CapGetNBCardInfo(CUSTOMERINFO *info)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		getcardinfo GetCardInfo;
		GetCardInfo = (getcardinfo)GetProcAddress(hdllInst, "CapGetNBCardInfo");
		if (GetCardInfo == NULL)
		{
			return -1701;
		}
		else
		{
			//CUSTOMERINFO *ctm_info;
			long status_getinfo = GetCardInfo(info);
			return status_getinfo;
		}
	}
}
//Ѱ��
long _stdcall CapNBQueryCard(long *UID)
{
	HMODULE  hdllInst = LoadLibraryA(CONDLL);
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
			long query_status = QueryCard(UID);
			const char* ipaddr = GetIPAddrINI();
			short port = GetPortINI();
			char recv_buf = '9';
			long getblack_status = GetBlack_limit(ipaddr, port, *UID, &recv_buf);
			if (getblack_status == 0)
			{
				//socket����ֵΪ1����ʾ�˿�UID�ں���������
				if (recv_buf == '1')
				{
					is_black = -1;
					FreeLibrary(hdllInst);
					return 463;
				}
				//socket����ֵΪ2����ʾ�ӿڷ����쳣������������
				if (recv_buf == '2')
				{
					int i = 0;
					int max_count = 3;
					while ((recv_buf == '2') && (i < max_count))
					{
						GetBlackList(ipaddr, port, *UID, &recv_buf);
						i++;
					}
					switch (recv_buf)
					{
					case '2':
						is_black = 0;
						FreeLibrary(hdllInst);
						return 404;
						break;
					case '1':
						is_black = -1;
						FreeLibrary(hdllInst);
						return 463;
						break;
					case '0':
						is_black = 1;
						FreeLibrary(hdllInst);
						return query_status;
						break;
					default:
						FreeLibrary(hdllInst);
						return 51;
						break;
					}
				}
				else
				{
					is_black = 1;
					FreeLibrary(hdllInst);
					return query_status;
				}
			}

			else
			{
				FreeLibrary(hdllInst);
				return 404;					//��������֤�ӿ������쳣
			}
		}
	}
}
//�ۿ�
long _stdcall CapSetNBCardInfo(long objNo, long UID, long opFare, LPSTR jyDT, __int64 *psamID, long *psamJyNo, long *tac)
{
	if (is_black != 1)
	{
		return -777;
	}
	else
	{


		HMODULE hdllInst = LoadLibraryA(CONDLL);
		if (hdllInst == NULL)
		{
			return -1801;
		}
		else
		{
			setcardinfo Set_CardInfo = (setcardinfo)GetProcAddress(hdllInst, "CapSetNBCardInfo");
			if (Set_CardInfo == NULL)
			{
				FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				long _objNo = objNo;
				long _UID = UID;
				long _opFare = opFare;
				LPSTR _jyDT = jyDT;
				__int64* _psamID = psamID;
				long* _psamJyNo = psamJyNo;
				long* _tac = tac;
				long status_setinfo = Set_CardInfo(_objNo, _UID, _opFare, _jyDT, _psamID, _psamJyNo, _tac);
				FreeLibrary(hdllInst);
				return status_setinfo;
			}
		}
	}
}
//�ۿ�,PSAM_IDʹ��LPSTR
long _stdcall  CapSetNBCardInfo_temp(long objNo, long UID, long opFare, LPSTR jyDT, LPSTR psamID, long *psamJyNo, char *tac, int redix)
{
	if (is_black != 1)
	{
		return -777;
	}
	else
	{
		HMODULE hdllInst = LoadLibraryA(CONDLL);
		if (hdllInst == NULL)
		{
			return -1801;
		}
		else
		{
			setcardinfo_str Set_CardInfo = (setcardinfo_str)GetProcAddress(hdllInst, "CapSetNBCardInfo_str");
			if (Set_CardInfo == NULL)
			{
				FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				long _objNo = objNo;
				long _UID = UID;
				long _opFare = opFare;
				LPSTR _jyDT = jyDT;
				char temp[100];
				strcpy(temp, psamID);
				__int64 _psamID = atoll(temp);
				long* _psamJyNo = psamJyNo;
				char* _tac = tac;
				long status_setinfo = Set_CardInfo(_objNo, _UID, _opFare, _jyDT, &_psamID, _psamJyNo, _tac, redix);
				char ch_temp[254];
				psamID = _i64toa(_psamID, ch_temp, 10);
				FreeLibrary(hdllInst);
				return status_setinfo;
			}
		}
	}
}
//�ۿ�Ӵ�/���޶�ܣ�
long _stdcall CapSetNBCardInfo_LMT(long objNo, long UID, long opFare, LPSTR jyDT, long onceLmt, long dayLmt, __int64 *psamID, long *psamJyNo, long *tac)
{
	if (is_black != 1)
	{
		return -777;
	}
	else
	{


		HMODULE hdllInst = LoadLibraryA(CONDLL);
		if (hdllInst == NULL)
		{
			return -1801;
		}
		else
		{
			setcardinfoLMT Set_CardInfoLMT = (setcardinfoLMT)GetProcAddress(hdllInst, "CapSetNBCardInfo_LMT");
			if (Set_CardInfoLMT == NULL)
			{
				FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{

				long status_setinfoLMT = Set_CardInfoLMT(objNo, UID, opFare, jyDT, onceLmt, dayLmt, psamID, psamJyNo, tac);
				FreeLibrary(hdllInst);
				return status_setinfoLMT;
			}
		}
	}
}
//5.7.	�ۿ���޶����֤�������ѣ�
long _stdcall CapSetNBCardInfo_Verify(long objNo, long UID, long opFare, LPSTR jyDT, long onceLmt, long dayLmt, LPSTR pwd, __int64 *psamID, long *psamJyNo, long *tac)
{
	if (is_black != 1)
	{
		return -777;
	}
	else
	{
		HMODULE hdllInst = LoadLibraryA(CONDLL);
		if (hdllInst == NULL)
		{
			return -1801;
		}
		else
		{
			setcardinfoVerify Set_CardInfoVerify = (setcardinfoVerify)GetProcAddress(hdllInst, "CapSetNBCardInfo_Verify");
			if (Set_CardInfoVerify == NULL)
			{
				FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{

				long status_setinfoVerify = Set_CardInfoVerify(objNo, UID, opFare, jyDT, onceLmt, dayLmt, pwd, psamID, psamJyNo, tac);
				FreeLibrary(hdllInst);
				return status_setinfoVerify;
			}
		}
	}
}
//5.8.	�������ۼ�����
long _stdcall CapUpdateNBCardStatus(long opFare, LPSTR jyDT)
{
	if (is_black != 1)
	{
		return -777;
	}
	else
	{
		HMODULE hdllInst = LoadLibraryA(CONDLL);
		if (hdllInst == NULL)
		{
			return -1801;
		}
		else
		{
			updatecardstatus update_CardStatus = (updatecardstatus)GetProcAddress(hdllInst, "CapUpdateNBCardStatus");
			if (update_CardStatus == NULL)
			{
				FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{

				long status_updatecard = update_CardStatus(opFare, jyDT);
				FreeLibrary(hdllInst);
				return status_updatecard;
			}
		}
	}
}
//5.9.	���¿���/���޶�
long _stdcall CapSetNBCardStatus(long onceLmt, long dayLmt)
{
	if (is_black != 1)
	{
		return -777;
	}
	else
	{
		HMODULE hdllInst = LoadLibraryA(CONDLL);
		if (hdllInst == NULL)
		{
			return -1801;
		}
		else
		{
			setcardstatus set_CardStaus = (setcardstatus)GetProcAddress(hdllInst, "CapSetNBCardStatus");
			if (set_CardStaus == NULL)
			{
				FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				long status_setcardstatus = set_CardStaus(onceLmt, dayLmt);
				FreeLibrary(hdllInst);
				return status_setcardstatus;
			}
		}
	}
}
//5.10.	��������
long _stdcall CapSetCardPwd(LPSTR oldPwd, LPSTR newPwd)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		setcardPWD set_CardPWD = (setcardPWD)GetProcAddress(hdllInst, "CapSetCardPwd");
		if (set_CardPWD == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			long status_setPWD = set_CardPWD(oldPwd, newPwd);
			FreeLibrary(hdllInst);
			return status_setPWD;
		}
	}
}
//5.11.	��ֵ��ʼ��
long _stdcall CapChargeInit(long objNo, long fare, __int64 *termId, long *bFare, long *no, long *random, long *mac1)
{
	if (is_black)
	{
		return -777;
	}
	else
	{
		HMODULE hdllInst = LoadLibraryA(CONDLL);
		if (hdllInst == NULL)
		{
			return -1801;
		}
		else
		{
			chargeInit charge_init = (chargeInit)GetProcAddress(hdllInst, "CapChargeInit");
			if (charge_init == NULL)
			{
				FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				long status_chargeinit = charge_init(objNo, fare, termId, bFare, no, random, mac1);
				FreeLibrary(hdllInst);
				return status_chargeinit;
			}
		}
	}
}
//��ֵ
long _stdcall CapCharge(LPSTR dt, LPSTR mac2, LPSTR tac)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		capcharge cap_charge = (capcharge)GetProcAddress(hdllInst, "CapCharge");
		if (cap_charge == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			long status_capcharge = cap_charge(dt, mac2, tac);
			FreeLibrary(hdllInst);
			return status_capcharge;
		}
	}
}
//5.12.	�ۿTAC�����ַ�����
long _stdcall CapSetNBCardInfo_Str(long objNo, long uid, long opFare, LPSTR jyDT, __int64 *psamID, long *psamJyNo, char *tac, int redix)
{
	if (is_black)
	{
		return -777;
	}
	else
	{
		HMODULE hdllInst = LoadLibraryA(CONDLL);
		if (hdllInst == NULL)
		{
			return -1801;
		}
		else
		{
			setcardinfo_str set_cardstr = (setcardinfo_str)GetProcAddress(hdllInst, "CapSetNBCardInfo_Str");
			if (set_cardstr == NULL)
			{
				FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				long status_setcardstr = set_cardstr(objNo, uid, opFare, jyDT, psamID, psamJyNo, tac, redix);
				FreeLibrary(hdllInst);
				return status_setcardstr;
			}
		}
	}
}
//5.13.	��ȡtacֵ
long _stdcall CapGetConsumeTac(long no, LPSTR tac)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		gettac get_tac = (gettac)GetProcAddress(hdllInst, "CapGetConsumeTac");
		if (get_tac == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{

			long status_gettac = get_tac(no, tac);
			FreeLibrary(hdllInst);
			return status_gettac;
		}
	}
}
//��ȡʮ�ν��׼�¼
long _stdcall CapReadRecords(CONSUMEINFO* info)
{
	HMODULE hinstance = LoadLibraryA(CONDLL);
	if (hinstance == NULL)
	{
		return -1801;
	}
	else
	{
		readrecords records = (readrecords)GetProcAddress(hinstance, "CapReadRecords");
		if (records == NULL)
		{
			FreeLibrary(hinstance);
			return -1701;
		}
		else
		{
			CONSUMEINFO* _info = info;
			long s = records(_info);
			FreeLibrary(hinstance);
			return s;
		}
	}
}

/*========================================ʵ�־��񽡿����ӿ�=======================================================*/

HANDLE _stdcall OpenDevice(int port)
{
	HMODULE hinstance = LoadLibraryA(CONDLL);
	if (hinstance == NULL)
	{
		return (HANDLE)-1;
	}
	else
	{
		opendevice OPDV = (opendevice)GetProcAddress(hinstance, "OpenDevice");
		if (OPDV == NULL)
		{
			FreeLibrary(hinstance);
			return (HANDLE)-2;
		}
		else
		{
			HANDLE h_status = OPDV(port);
			FreeLibrary(hinstance);
			return h_status;
		}

	}
}
int _stdcall CloseDevice(HANDLE hdev)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		closedevice close_device = (closedevice)GetProcAddress(hdllInst, "CloseDevice");
		if (close_device == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			HANDLE _hdev = hdev;
			int status_closedevice = close_device(_hdev);
			FreeLibrary(hdllInst);
			return status_closedevice;
		}
	}

}
int _stdcall PowerOn(HANDLE hdev, int slot, char* atr)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		poweron power_on = (poweron)GetProcAddress(hdllInst, "PowerOn");
		if (power_on == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			HANDLE _hdev = hdev;
			int _slot = slot;
			char* _atr = atr;
			int status_poweron = power_on(hdev, slot, atr);
			return status_poweron;
		}
	}
}
int _stdcall SendAPDU(HANDLE hdev, unsigned char byslot, unsigned char* pbyccommand, unsigned long len, unsigned char* pbyrcommand, int* pnrs)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		sendapdu send_apdu = (sendapdu)GetProcAddress(hdllInst, "SendAPDU");
		if (send_apdu == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			HANDLE _hdev = hdev;
			unsigned char _byslot = byslot;
			unsigned char* _pbyc = pbyccommand;
			unsigned long _len = len;
			unsigned char* _pbyr = pbyrcommand;
			int* _pnrs = pnrs;
			int stauts_sendapdu = send_apdu(_hdev, _byslot, _pbyc, _len, _pbyr, _pnrs);
			FreeLibrary(hdllInst);
			return stauts_sendapdu;
		}
	}
}
int _stdcall iR_DDF1EF05Info(HANDLE hdev, char* klb, char* gfbb, char* fkjgmc, char* fkjgdm, char* fkjgzs, char* fksj, char* kh, char* aqm, char* xpxlh, char* yycsdm)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_ddf1ef05 ef05 = (r_ddf1ef05)GetProcAddress(hdllInst, "iR_DDF1EF05Info");
		if (ef05 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_ef05 = ef05(hdev, klb, gfbb, fkjgmc, fkjgdm, fkjgzs, fksj, kh, aqm, xpxlh, yycsdm);
			FreeLibrary(hdllInst);
			return stauts_ef05;
		}
	}
}
int _stdcall iW_DDF1EF05Info(HANDLE hdev, char* klb, char* gfbb, char* fkjgmc, char* fkjgdm, char* fkjgzs, char* fksj, char* kh, char* aqm, char* xpxlh, char* yycsdm)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_ddf1ef05 ef05 = (w_ddf1ef05)GetProcAddress(hdllInst, "iW_DDF1EF05Info");
		if (ef05 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{

			int stauts_ef05 = ef05(hdev, klb, gfbb, fkjgmc, fkjgdm, fkjgzs, fksj, kh, aqm, xpxlh, yycsdm);
			FreeLibrary(hdllInst);
			return stauts_ef05;
		}
	}
}
int _stdcall iR_DDF1EF06Info(HANDLE hdev, char* xm, char* xb, char* mz, char* csrq, char* sfzh)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_ddf1ef06 ef06 = (r_ddf1ef06)GetProcAddress(hdllInst, "iR_DDF1EF06Info");
		if (ef06 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{

			int stauts_ef06 = ef06(hdev, xm, xb, mz, csrq, sfzh);
			FreeLibrary(hdllInst);
			return stauts_ef06;
		}
	}
}
int _stdcall iW_DDF1EF06Info(HANDLE hdev, char* xm, char* xb, char* mz, char* csrq, char* sfzh)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_ddf1ef06 ef06 = (w_ddf1ef06)GetProcAddress(hdllInst, "iW_DDF1EF06Info");
		if (ef06 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{

			int stauts_ef06 = ef06(hdev, xm, xb, mz, csrq, sfzh);
			FreeLibrary(hdllInst);
			return stauts_ef06;
		}
	}
}
int _stdcall iR_DDF1EF07Info(HANDLE hdev, char* zp_path)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df1ef07 ef07 = (r_df1ef07)GetProcAddress(hdllInst, "iR_DDF1EF07Info");
		if (ef07 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{

			int stauts_ef07 = ef07(hdev, zp_path);
			FreeLibrary(hdllInst);
			return stauts_ef07;
		}
	}
}
int _stdcall iW_DDF1EF07Info(HANDLE hdev, char* zp_path)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df1ef07 ef07 = (w_df1ef07)GetProcAddress(hdllInst, "iW_DDF1EF07Info");
		if (ef07 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{

			int stauts_ef07 = ef07(hdev, zp_path);
			FreeLibrary(hdllInst);
			return stauts_ef07;
		}
	}
}
int _stdcall iR_DDF1EF08Info(HANDLE hdev, char* kyxq, char* brdh1, char* brdh2, char* ylfs1, char* ylfs2, char* ylfs3)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_ddf1ef08 ef08 = (r_ddf1ef08)GetProcAddress(hdllInst, "iR_DDF1EF08Info");
		if (ef08 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{

			int stauts_ef08 = ef08(hdev, kyxq, brdh1, brdh2, ylfs1, ylfs2, ylfs3);
			FreeLibrary(hdllInst);
			return stauts_ef08;
		}
	}
}
int _stdcall iW_DDF1EF08Info(HANDLE hdev, char* kyxq, char* brdh1, char* brdh2, char* ylfs1, char* ylfs2, char* ylfs3)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_ddf1ef08 ef08 = (w_ddf1ef08)GetProcAddress(hdllInst, "iW_DDF1EF08Info");
		if (ef08 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{

			int stauts_ef08 = ef08(hdev, kyxq, brdh1, brdh2, ylfs1, ylfs2, ylfs3);
			FreeLibrary(hdllInst);
			return stauts_ef08;
		}
	}
}
int _stdcall iR_DF01EF05Info(HANDLE hdev, char* dzlb1, char* dz1, char* dzlb2, char* dz2)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df01ef05 df01ef05 = (r_df01ef05)GetProcAddress(hdllInst, "iR_DF01EF05Info");
		if (df01ef05 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{

			int stauts_df01ef05 = df01ef05(hdev, dzlb1, dz1, dzlb2, dz2);
			FreeLibrary(hdllInst);
			return stauts_df01ef05;
		}
	}
}
int _stdcall iW_DF01EF05Info(HANDLE hdev, char* dzlb1, char* dz1, char* dzlb2, char* dz2)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df01ef05 df01ef05 = (w_df01ef05)GetProcAddress(hdllInst, "iW_DF01EF05Info");
		if (df01ef05 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df01ef05 = df01ef05(hdev, dzlb1, dz1, dzlb2, dz2);
			FreeLibrary(hdllInst);
			return stauts_df01ef05;
		}
	}
}
int _stdcall iR_DF01EF06Info(HANDLE hdev, char* xm1, char* gx1, char* dh1, char* xm2, char* gx2, char* dh2, char* xm3, char* gx3, char* dh3)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df01ef06 df01ef06 = (r_df01ef06)GetProcAddress(hdllInst, "iR_DF01EF06Info");
		if (df01ef06 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			HANDLE _hdev = hdev;
			char* _xm1 = xm1;
			char* _gx1 = gx1;
			char* _dh1 = dh1;
			char* _xm2 = xm2;
			char* _gx2 = gx2;
			char* _dh2 = dh2;
			char* _xm3 = xm3;
			char* _gx3 = gx3;
			char* _dh3 = dh3;
			int stauts_df01ef06 = df01ef06(_hdev, _xm1, _gx1, _dh1, _xm2, _gx2, _dh2, _xm3, _gx3, _dh3);
			FreeLibrary(hdllInst);
			return stauts_df01ef06;
		}
	}
}
int _stdcall iW_DF01EF06Info(HANDLE hdev, char* xm1, char* gx1, char* dh1, char* xm2, char* gx2, char* dh2, char* xm3, char* gx3, char* dh3)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df01ef06 df01ef06 = (w_df01ef06)GetProcAddress(hdllInst, "iW_DF01EF06Info");
		if (df01ef06 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df01ef06 = df01ef06(hdev, xm1, gx1, dh1, xm2, gx2, dh2, xm3, gx3, dh3);
			FreeLibrary(hdllInst);
			return stauts_df01ef06;
		}
	}
}
int _stdcall iR_DF01EF07Info(HANDLE hdev, char* whcd, char* hyzk, char* zy)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df01ef07 df01ef07 = (r_df01ef07)GetProcAddress(hdllInst, "iR_DF01EF07Info");
		if (df01ef07 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df01ef07 = df01ef07(hdev, whcd, hyzk, zy);
			FreeLibrary(hdllInst);
			return stauts_df01ef07;
		}
	}
}
int _stdcall iW_DF01EF07Info(HANDLE hdev, char* whcd, char* hyzk, char* zy)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df01ef07 df01ef07 = (w_df01ef07)GetProcAddress(hdllInst, "iW_DF01EF07Info");
		if (df01ef07 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df01ef07 = df01ef07(hdev, whcd, hyzk, zy);
			FreeLibrary(hdllInst);
			return stauts_df01ef07;
		}
	}
}
int _stdcall iR_DF01EF08Info(HANDLE hdev, char* zjlb, char* zjhm, char* jkdah, char* xnhzh)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df01ef08 df01ef08 = (r_df01ef08)GetProcAddress(hdllInst, "iR_DF01EF08Info");
		if (df01ef08 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df01ef08 = df01ef08(hdev, zjlb, zjhm, jkdah, xnhzh);
			FreeLibrary(hdllInst);
			return stauts_df01ef08;
		}
	}
}
int _stdcall iW_DF01EF08Info(HANDLE hdev, char* zjlb, char* zjhm, char* jkdah, char* xnhzh)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df01ef08 df01ef08 = (w_df01ef08)GetProcAddress(hdllInst, "iW_DF01EF08Info");
		if (df01ef08 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df01ef08 = df01ef08(hdev, zjlb, zjhm, jkdah, xnhzh);
			FreeLibrary(hdllInst);
			return stauts_df01ef08;
		}
	}
}
int _stdcall iR_DF02EF05Info(HANDLE hdev, char* abo, char* rh, char* xc, char* xzb, char* xnxgb, char* dxb, char* nxwl, char* tnb, char* qgy, char* tx, char* qgyz, char* qgqs, char* kzxyz, char* xzqbq, char* qtyxjs)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df02ef05 df02ef05 = (r_df02ef05)GetProcAddress(hdllInst, "iR_DF02EF05Info");
		if (df02ef05 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df02ef05 = df02ef05(hdev, abo, rh, xc, xzb, xnxgb, dxb, nxwl, tnb, qgy, tx, qgyz, qgqs, kzxyz, xzqbq, qtyxjs);
			FreeLibrary(hdllInst);
			return stauts_df02ef05;
		}
	}
}
int _stdcall iW_DF02EF05Info(HANDLE hdev, char* abo, char* rh, char* xc, char* xzb, char* xnxgb, char* dxb, char* nxwl, char* tnb, char* qgy, char* tx, char* qgyz, char* qgqs, char* kzxyz, char* xzqbq, char* qtyxjs)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df02ef05 df02ef05 = (w_df02ef05)GetProcAddress(hdllInst, "iW_DF02EF05Info");
		if (df02ef05 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df02ef05 = df02ef05(hdev, abo, rh, xc, xzb, xnxgb, dxb, nxwl, tnb, qgy, tx, qgyz, qgqs, kzxyz, xzqbq, qtyxjs);
			FreeLibrary(hdllInst);
			return stauts_df02ef05;
		}
	}
}
int _stdcall iR_DF02EF06Info(HANDLE hdev, char* jsb)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df02ef06 df02ef06 = (r_df02ef06)GetProcAddress(hdllInst, "iR_DF02EF06Info");
		if (df02ef06 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df02ef06 = df02ef06(hdev, jsb);
			FreeLibrary(hdllInst);
			return stauts_df02ef06;
		}
	}
}
int _stdcall iW_DF02EF06Info(HANDLE hdev, char* jsb)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df02ef06 df02ef06 = (w_df02ef06)GetProcAddress(hdllInst, "iW_DF02EF06Info");
		if (df02ef06 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df02ef06 = df02ef06(hdev, jsb);
			FreeLibrary(hdllInst);
			return stauts_df02ef06;
		}
	}
}
int _stdcall iR_DF02EF07Info(HANDLE hdev, int recordNo, char* gmwz, char* gmmc)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df02ef07 df02ef07 = (r_df02ef07)GetProcAddress(hdllInst, "iR_DF02EF07Info");
		if (df02ef07 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df02ef07 = df02ef07(hdev, recordNo, gmwz, gmmc);
			FreeLibrary(hdllInst);
			return stauts_df02ef07;
		}
	}
}
int _stdcall iW_DF02EF07Info(HANDLE hdev, char* gmwz, char* gmmc)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df02ef07 df02ef07 = (w_df02ef07)GetProcAddress(hdllInst, "iW_DF02EF07Info");
		if (df02ef07 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df02ef07 = df02ef07(hdev, gmwz, gmmc);
			FreeLibrary(hdllInst);
			return stauts_df02ef07;
		}
	}
}
int _stdcall iR_DF02EF08Info(HANDLE hdev, int recordNo, char* jzmc, char* jzsj)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df02ef08 df02ef08 = (r_df02ef08)GetProcAddress(hdllInst, "iR_DF02EF08Info");
		if (df02ef08 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df02ef08 = df02ef08(hdev, recordNo, jzmc, jzsj);
			FreeLibrary(hdllInst);
			return stauts_df02ef08;
		}
	}
}
int _stdcall iW_DF02EF08Info(HANDLE hdev, char* jzmc, char* jzsj)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df02ef08 df02ef08 = (w_df02ef08)GetProcAddress(hdllInst, "iW_DF02EF08Info");
		if (df02ef08 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df02ef08 = df02ef08(hdev, jzmc, jzsj);
			FreeLibrary(hdllInst);
			return stauts_df02ef08;
		}
	}
}
int _stdcall iR_DF03EF05Info(HANDLE hdev, char* jl1, char* jl2, char* jl3)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df03ef05 df03ef05 = (r_df03ef05)GetProcAddress(hdllInst, "iR_DF03EF05Info");
		if (df03ef05 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df03ef05 = df03ef05(hdev, jl1, jl2, jl3);
			FreeLibrary(hdllInst);
			return stauts_df03ef05;
		}
	}
}
int _stdcall iW_DF03EF05Info(HANDLE hdev, int recordNo)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df03ef05 df03ef05 = (w_df03ef05)GetProcAddress(hdllInst, "iW_DF03EF05Info");
		if (df03ef05 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df03ef05 = df03ef05(hdev, recordNo);
			FreeLibrary(hdllInst);
			return stauts_df03ef05;
		}
	}
}
int _stdcall iErase_DF03EF05Info(HANDLE hdev, int recordNo)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		e_df03ef05 df03ef05 = (e_df03ef05)GetProcAddress(hdllInst, "iErase_DF03EF05Info");
		if (df03ef05 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df03ef05 = df03ef05(hdev, recordNo);
			FreeLibrary(hdllInst);
			return stauts_df03ef05;
		}
	}
}
int _stdcall iR_DF03EF06Info(HANDLE hdev, char* mzbs1, char* mzbs2, char* mzbs3, char* mzbs4, char* mzbs5)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df03ef06 df03ef06 = (r_df03ef06)GetProcAddress(hdllInst, "iR_DF03EF06Info");
		if (df03ef06 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df03ef06 = df03ef06(hdev, mzbs1, mzbs2, mzbs3, mzbs4, mzbs5);
			FreeLibrary(hdllInst);
			return stauts_df03ef06;
		}
	}
}
int _stdcall iW_DF03EF06Info(HANDLE hdev, int record)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df03ef06 df03ef06 = (w_df03ef06)GetProcAddress(hdllInst, "iW_DF03EF06Info");
		if (df03ef06 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df03ef06 = df03ef06(hdev, record);
			FreeLibrary(hdllInst);
			return stauts_df03ef06;
		}
	}
}
int _stdcall iErase_DF03EF06Info(HANDLE hdev, int record)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		e_df03ef06 df03ef06 = (e_df03ef06)GetProcAddress(hdllInst, "iErase_DF03EF06Info");
		if (df03ef06 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df03ef06 = df03ef06(hdev, record);
			FreeLibrary(hdllInst);
			return stauts_df03ef06;
		}
	}
}
int _stdcall iR_DF03EEInfo(HANDLE hdev, int record, char* szdata, int npos, int nlen, int nstyle)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df03ee df03ee = (r_df03ee)GetProcAddress(hdllInst, "iR_DF03EEInfo");
		if (df03ee == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df03ee = df03ee(hdev, record, szdata, npos, nlen, nstyle);
			FreeLibrary(hdllInst);
			return stauts_df03ee;
		}
	}
}
int _stdcall iW_DF03EEInfo(HANDLE hdev, int record, char* szdata, int npos, int nlen, int nstyle)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df03ee df03ee = (w_df03ee)GetProcAddress(hdllInst, "iW_DF03EEInfo");
		if (df03ee == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df03ee = df03ee(hdev, record, szdata, npos, nlen, nstyle);
			FreeLibrary(hdllInst);
			return stauts_df03ee;
		}
	}
}
int _stdcall iR_DF03EDInfo(HANDLE hdev, int record, char* szdata, int npos, int nlen, int nstyle)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		r_df03ed df03ed = (r_df03ed)GetProcAddress(hdllInst, "iR_DF03EDInfo");
		if (df03ed == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df03ed = df03ed(hdev, record, szdata, npos, nlen, nstyle);
			FreeLibrary(hdllInst);
			return stauts_df03ed;
		}
	}
}
int _stdcall iW_DF03EDInfo(HANDLE hdev, int record, char* szdata, int npos, int nlen, int nstyle)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		w_df03ed df03ed = (w_df03ed)GetProcAddress(hdllInst, "iW_DF03EDInfo");
		if (df03ed == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_df03ed = df03ed(hdev, record, szdata, npos, nlen, nstyle);
			FreeLibrary(hdllInst);
			return stauts_df03ed;
		}
	}
}
int _stdcall SM3Digest(HANDLE hdev, BYTE* pbdata, int len, BYTE* pbhash, BYTE* pbhashlen)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		sm3 _sm3 = (sm3)GetProcAddress(hdllInst, "SM3Digest");
		if (_sm3 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_sm3 = _sm3(hdev, pbdata, len, pbhash, pbhashlen);
			FreeLibrary(hdllInst);
			return stauts_sm3;
		}
	}
}
int _stdcall VerifyPin(HANDLE hdev, char* szpin, BYTE* pwdretry)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		verifypin pin = (verifypin)GetProcAddress(hdllInst, "VerifyPin");
		if (pin == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_pin = pin(hdev, szpin, pwdretry);
			FreeLibrary(hdllInst);
			return stauts_pin;
		}
	}
}
int _stdcall SM2SignHash(HANDLE hdev, BYTE* pbdata, int len, BYTE* pbhash, BYTE* pbhashlen)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		sm2 _sm2 = (sm2)GetProcAddress(hdllInst, "SM2SignHash");
		if (_sm2 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int stauts_sm2 = _sm2(hdev, pbdata, len, pbhash, pbhashlen);
			FreeLibrary(hdllInst);
			return stauts_sm2;
		}
	}
}
int _stdcall IReader_GetDeviceCSN(HANDLE hdev, char* info)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		getcsn get_csn = (getcsn)GetProcAddress(hdllInst, "IReader_GetDeviceCSN");
		if (get_csn == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int status_csn = get_csn(hdev, info);
			FreeLibrary(hdllInst);
			return status_csn;
		}
	}
}
int _stdcall iReader_SAM_Public(HANDLE hdev, char* info)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		getsam get_sam = (getsam)GetProcAddress(hdllInst, "iReader_SAM_Public");
		if (get_sam == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int status_sam = get_sam(hdev, info);
			FreeLibrary(hdllInst);
			return status_sam;
		}
	}
}
int _stdcall iReader_GetLastEEIndex(HANDLE hdev)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		get_eeindex eeindex = (get_eeindex)GetProcAddress(hdllInst, "iReader_GetLastEEIndex");
		if (eeindex == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int status_eeindex = eeindex(hdev);
			FreeLibrary(hdllInst);
			return status_eeindex;
		}
	}
}
int _stdcall iReader_GetLastEDIndex(HANDLE hdev)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		get_edindex edindex = (get_edindex)GetProcAddress(hdllInst, "iReader_GetLastEDIndex");
		if (edindex == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int status_edindex = edindex(hdev);
			FreeLibrary(hdllInst);
			return status_edindex;
		}
	}
}
int _stdcall LockPersonalInfo(HANDLE hdev)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		lockinfo lock_info = (lockinfo)GetProcAddress(hdllInst, "LockPersonalInfo");
		if (lock_info == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			int status_lock = lock_info(hdev);
			FreeLibrary(hdllInst);
			return status_lock;
		}
	}
}

int _stdcall XDT_GetHisInfo(HANDLE hdev, char* cardno, long* ye, char* xm, char* xb, char* csrq, char* sfzhm)
{
	HMODULE hdllInst = LoadLibraryA(CONDLL);
	if (hdllInst == NULL)
	{
		return -1801;
	}
	else
	{
		//����ͨ��ȡ�ͻ���Ϣ
		CUSTOMERINFO info;
		getcardinfo GetCardInfo;
		GetCardInfo = (getcardinfo)GetProcAddress(hdllInst, "CapGetNBCardInfo");
		if (GetCardInfo == NULL)
		{
			return -1701;
		}
		else
		{
			//CUSTOMERINFO *ctm_info;
			long status_getinfo = GetCardInfo(&info);
			cardno = info.CityCardNo;
			*ye = info.Ye;
			//xm = info.Name;
		}
		//�������ϵ�
		char _atr[64];
		poweron jkk_poweron = (poweron)GetProcAddress(hdllInst, "PowerOn");
		long s_pn1 = jkk_poweron(hdev, 1, _atr);
		long s_pn3 = jkk_poweron(hdev, 3, _atr);
		//����������
		r_ddf1ef06 ef06 = (r_ddf1ef06)GetProcAddress(hdllInst, "iR_DDF1EF06Info");
		if (ef06 == NULL)
		{
			FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			char mz[12];
			int stauts_ef06 = ef06(hdev, xm, xb, mz, csrq, sfzhm);
			FreeLibrary(hdllInst);
			return stauts_ef06;
		}
	}
}