// WSBDLL.cpp : ���� DLL Ӧ�ó���ĵ���������
//
#include "stdafx.h"

#include <stdlib.h>
#include "MyCode.h"
#include <WinSock2.h>
#include "iostream"
#include <io.h>
#include <direct.h>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <thread>
#include"json\json.h"
#include "scan\chuankou.h"
#pragma comment(lib,"ws2_32.lib")
#include <comdef.h>
#include <string.h>
#include <sstream>
//AES����ͷ�ļ�
//#include "aes.h";
//#include "aes_encryptor.h";
//ʹ��Cryptoo++��

using namespace std;
//���������״̬,��ʼֵΪ0����֤�������Ϊ-1���Ǻ�����Ϊ1
int is_black = 0;
int HDDTYPE = -1; //Ӳ�����ͣ�1��E711;	2:W2160;
int RTYPE = -1;	//��ǰ�������ͣ�ʵ�忨Ϊ1�����ӽ�����Ϊ2
const int T = 200;
LPCSTR CONDLL = "HealthyCarder.dll";
LPCSTR CAPDLL = "Cap_RW.dll";
LPCSTR DCHDLL = "DCHealthyCarder.dll";
LPCSTR DCDLL = "dcrf32.dll";
//LPSTR iniFileName = ".\\ChgCity.ini";
char iniFileName[20] = ".\\ChgCity.ini";
LPSTR RIZHI = "debug.log";
Json::Value js_vl;
char ALLIDCARD[20] = { 0 };
HMODULE HIns_CAP = LoadLibraryA(CAPDLL);
HMODULE HIns_WQ = LoadLibraryA(CONDLL);
HMODULE HIns_DC_HEL = LoadLibraryA(DCHDLL);
HMODULE HIns_DC = LoadLibraryA(DCDLL);
#define COMMONERROR 100;
#define OUTTIME 102;

#pragma region ����һ��ͨ�ӿ�
//int seq = 1;
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
typedef long(WINAPI *setcardinfo)(long, long, long, LPSTR, __int64*, long*, __int64*);
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
//5.15.�ۿpsam���š�TAC�����ַ�����
typedef long(WINAPI *setcardinfo_str1)(long, long, long, LPSTR, char*, long*, char*, int);
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
typedef int(WINAPI *readcardinfo)(char*, char*);
//6.2.2	���ֿ��˻�����Ϣ�����ļ��ӿ�
typedef int(WINAPI *readpersoninfo)(char*, char*);
/*���½ӿ������ڸ��˻�����Ϣ��
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
*/
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
typedef int(WINAPI *readEEinfo)(int, char*, char*);
//дסԺ��Ϣ�ļ��ӿ�
typedef int(WINAPI *writeEEinfo)(char*, char*);
//����������Ϣ�ļ��ӿ�
typedef int(WINAPI *readEDinfo)(int, char*, char*);
//д��������Ϣ�ļ��ӿ�
typedef int(WINAPI *writeEDinfo)(char*, char*);
//6.3.1	SM3ժҪ
typedef int(WINAPI *sm3)(HANDLE, BYTE*, int, BYTE*, BYTE*);
//6.3.2	PIN��֤����
typedef int(WINAPI *verifypin)(HANDLE, const char*, BYTE*);
//6.3.3	SM2ǩ������
typedef int(WINAPI *sm2)(HANDLE, BYTE*, BYTE, BYTE*, BYTE*);
//��ȡ�豸���к���Ϣ
typedef int(WINAPI *readDevNum)(char*, char*);
//��ȡSAM������Ϣ
typedef int(WINAPI *readSamNum)(char*, char*);
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
//�����ȡ��ά��ӿ�
typedef int(WINAPI *sendscancmd)(char*, char*);
//���������Զ�ɨ��ӿ�
typedef int(WINAPI *checkmodauto)(char*, char*);
//��������ָ��ɨ��ģʽ
typedef int(WINAPI *checkmodcmd)(char*, char*);
//�����ȡ��ǰɨ��ģʽ
typedef int(WINAPI *getscanmod)(char*, char*);
//@
//6.2.1	�������������������ļ��ӿ�
typedef int(WINAPI *r_ddf1ef05)(HANDLE, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*);
//6.2.2	���ֿ��˻�����Ϣ�����ļ��ӿ�
typedef int(WINAPI *r_ddf1ef06)(HANDLE, char*, char*, char*, char*, char*);
//����Ч�ڵ��ļ��ӿ�
typedef int(WINAPI *r_ddf1ef08)(HANDLE, char*, char*, char*, char*, char*, char*);
//����ַ��Ϣ�ļ��ӿ�
typedef int(WINAPI *r_df01ef05)(HANDLE, char*, char*, char*, char*);
//����ϵ����Ϣ�ļ��ӿ�
typedef int(WINAPI *r_df01ef06)(HANDLE, char*, char*, char*, char*, char*, char*, char*, char*, char*);
//��ְҵ������Ϣ�ļ��ӿ�
typedef int(WINAPI *r_df01ef07)(HANDLE, char*, char*, char*);
//��סԺ��Ϣ�ļ��ӿ�
typedef int(WINAPI *r_df03ee)(HANDLE, int, char*, int, int, int);
//дסԺ��Ϣ�ļ��ӿ�
typedef int(WINAPI *w_df03ee)(HANDLE, int, char*, int, int, int);
//����������Ϣ�ļ��ӿ�
typedef int(WINAPI *r_df03ed)(HANDLE, int, char*, int, int, int);
//д��������Ϣ�ļ��ӿ�
typedef int(WINAPI *w_df03ed)(HANDLE, int, char*, int, int, int);
//��������Ϣ�ۺϽӿ�
typedef int(WINAPI *r_pinfo)(int, char*, char*);

#pragma endregion

#pragma region ����¿��ӿ�

typedef HANDLE(WINAPI *dcinit)(int, int);
//��ʼɨ��
typedef int(WINAPI *dc_startscan)(HANDLE, unsigned char);
//��ȡɨ������
typedef int(WINAPI *dc_getscandata)(HANDLE, int*, unsigned char*);
//����ɨ��
typedef int(WINAPI *dc_sacnexit)(HANDLE);
//�رն������˿�
typedef int(WINAPI *dc_exit)(HANDLE);
//�¿����񽡿���
//���豸
typedef HANDLE(WINAPI *dc_open)(int);
//�ر��豸
typedef int(WINAPI *dc_close)(HANDLE);
//�ϵ縴λ
typedef int(WINAPI *dc_poweron)(HANDLE, int, char*);
//����������Ϣ
typedef int(WINAPI *dc_ref05)(HANDLE, char*, char*, char*, char*, char*, char*, char*, char*, char*, char*);
//����
typedef int(WINAPI *dc_beep)(HANDLE, unsigned short);
#pragma endregion
#pragma region MD5����


typedef  unsigned  char  *POINTER;
typedef  unsigned  short  int  UINT2;
typedef  unsigned  long  int  UINT4;

typedef  struct
{
	UINT4  state[4];
	UINT4  count[2];
	unsigned  char  buffer[64];
}  MD5_CTX;


void  MD5Init(MD5_CTX  *);
void  MD5Update(MD5_CTX  *, unsigned  char  *, unsigned  int);
void  MD5Final(unsigned  char[16], MD5_CTX  *);

#define  S11  7 
#define  S12  12 
#define  S13  17 
#define  S14  22 
#define  S21  5 
#define  S22  9 
#define  S23  14 
#define  S24  20 
#define  S31  4 
#define  S32  11 
#define  S33  16 
#define  S34  23 
#define  S41  6 
#define  S42  10 
#define  S43  15 
#define  S44  21 

static  unsigned  char  PADDING[64] = {
	0x80,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
};

#define  F(x,  y,  z)  (((x)  &  (y))  |  ((~x)  &  (z))) 
#define  G(x,  y,  z)  (((x)  &  (z))  |  ((y)  &  (~z))) 
#define  H(x,  y,  z)  ((x)  ^  (y)  ^  (z)) 
#define  I(x,  y,  z)  ((y)  ^  ((x)  |  (~z))) 

#define  ROTATE_LEFT(x,  n)  (((x)  <<  (n))  |  ((x)  >>  (32-(n)))) 

#define  FF(a,  b,  c,  d,  x,  s,  ac)  {   (a)  +=  F  ((b),  (c),  (d))  +  (x)  +  (UINT4)(ac);   (a)  =  ROTATE_LEFT  ((a),  (s));   (a)  +=  (b);    } 
#define  GG(a,  b,  c,  d,  x,  s,  ac)  {   (a)  +=  G  ((b),  (c),  (d))  +  (x)  +  (UINT4)(ac);   (a)  =  ROTATE_LEFT  ((a),  (s));   (a)  +=  (b);    } 
#define  HH(a,  b,  c,  d,  x,  s,  ac)  {   (a)  +=  H  ((b),  (c),  (d))  +  (x)  +  (UINT4)(ac);   (a)  =  ROTATE_LEFT  ((a),  (s));   (a)  +=  (b);    } 
#define  II(a,  b,  c,  d,  x,  s,  ac)  {   (a)  +=  I  ((b),  (c),  (d))  +  (x)  +  (UINT4)(ac);   (a)  =  ROTATE_LEFT  ((a),  (s));   (a)  +=  (b);  } 


inline  void  Encode(unsigned  char  *output, UINT4  *input, unsigned  int  len)
{
	unsigned  int  i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned  char)(input[i] & 0xff);
		output[j + 1] = (unsigned  char)((input[i] >> 8) & 0xff);
		output[j + 2] = (unsigned  char)((input[i] >> 16) & 0xff);
		output[j + 3] = (unsigned  char)((input[i] >> 24) & 0xff);
	}
}

inline  void  Decode(UINT4  *output, unsigned  char  *input, unsigned  int  len)
{
	unsigned  int  i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((UINT4)input[j]) | (((UINT4)input[j + 1]) << 8) |
		(((UINT4)input[j + 2]) << 16) | (((UINT4)input[j + 3]) << 24);
}

inline  void  MD5Transform(UINT4  state[4], unsigned  char  block[64])
{
	UINT4  a = state[0], b = state[1], c = state[2], d = state[3], x[16];
	Decode(x, block, 64);
	FF(a, b, c, d, x[0], S11, 0xd76aa478);
	FF(d, a, b, c, x[1], S12, 0xe8c7b756);
	FF(c, d, a, b, x[2], S13, 0x242070db);
	FF(b, c, d, a, x[3], S14, 0xc1bdceee);
	FF(a, b, c, d, x[4], S11, 0xf57c0faf);
	FF(d, a, b, c, x[5], S12, 0x4787c62a);
	FF(c, d, a, b, x[6], S13, 0xa8304613);
	FF(b, c, d, a, x[7], S14, 0xfd469501);
	FF(a, b, c, d, x[8], S11, 0x698098d8);
	FF(d, a, b, c, x[9], S12, 0x8b44f7af);
	FF(c, d, a, b, x[10], S13, 0xffff5bb1);
	FF(b, c, d, a, x[11], S14, 0x895cd7be);
	FF(a, b, c, d, x[12], S11, 0x6b901122);
	FF(d, a, b, c, x[13], S12, 0xfd987193);
	FF(c, d, a, b, x[14], S13, 0xa679438e);
	FF(b, c, d, a, x[15], S14, 0x49b40821);
	GG(a, b, c, d, x[1], S21, 0xf61e2562);
	GG(d, a, b, c, x[6], S22, 0xc040b340);
	GG(c, d, a, b, x[11], S23, 0x265e5a51);
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);
	GG(a, b, c, d, x[5], S21, 0xd62f105d);
	GG(d, a, b, c, x[10], S22, 0x2441453);
	GG(c, d, a, b, x[15], S23, 0xd8a1e681);
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);
	GG(a, b, c, d, x[9], S21, 0x21e1cde6);
	GG(d, a, b, c, x[14], S22, 0xc33707d6);
	GG(c, d, a, b, x[3], S23, 0xf4d50d87);
	GG(b, c, d, a, x[8], S24, 0x455a14ed);
	GG(a, b, c, d, x[13], S21, 0xa9e3e905);
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8);
	GG(c, d, a, b, x[7], S23, 0x676f02d9);
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);
	HH(a, b, c, d, x[5], S31, 0xfffa3942);
	HH(d, a, b, c, x[8], S32, 0x8771f681);
	HH(c, d, a, b, x[11], S33, 0x6d9d6122);
	HH(b, c, d, a, x[14], S34, 0xfde5380c);
	HH(a, b, c, d, x[1], S31, 0xa4beea44);
	HH(d, a, b, c, x[4], S32, 0x4bdecfa9);
	HH(c, d, a, b, x[7], S33, 0xf6bb4b60);
	HH(b, c, d, a, x[10], S34, 0xbebfbc70);
	HH(a, b, c, d, x[13], S31, 0x289b7ec6);
	HH(d, a, b, c, x[0], S32, 0xeaa127fa);
	HH(c, d, a, b, x[3], S33, 0xd4ef3085);
	HH(b, c, d, a, x[6], S34, 0x4881d05);
	HH(a, b, c, d, x[9], S31, 0xd9d4d039);
	HH(d, a, b, c, x[12], S32, 0xe6db99e5);
	HH(c, d, a, b, x[15], S33, 0x1fa27cf8);
	HH(b, c, d, a, x[2], S34, 0xc4ac5665);
	II(a, b, c, d, x[0], S41, 0xf4292244);
	II(d, a, b, c, x[7], S42, 0x432aff97);
	II(c, d, a, b, x[14], S43, 0xab9423a7);
	II(b, c, d, a, x[5], S44, 0xfc93a039);
	II(a, b, c, d, x[12], S41, 0x655b59c3);
	II(d, a, b, c, x[3], S42, 0x8f0ccc92);
	II(c, d, a, b, x[10], S43, 0xffeff47d);
	II(b, c, d, a, x[1], S44, 0x85845dd1);
	II(a, b, c, d, x[8], S41, 0x6fa87e4f);
	II(d, a, b, c, x[15], S42, 0xfe2ce6e0);
	II(c, d, a, b, x[6], S43, 0xa3014314);
	II(b, c, d, a, x[13], S44, 0x4e0811a1);
	II(a, b, c, d, x[4], S41, 0xf7537e82);
	II(d, a, b, c, x[11], S42, 0xbd3af235);
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb);
	II(b, c, d, a, x[9], S44, 0xeb86d391);
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	memset((POINTER)x, 0, sizeof(x));
}

inline  void  MD5Init(MD5_CTX  *context)
{
	context->count[0] = context->count[1] = 0;
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

inline  void  MD5Update(MD5_CTX  *context, unsigned  char  *input, unsigned  int  inputLen)
{
	unsigned  int  i, index, partLen;

	index = (unsigned  int)((context->count[0] >> 3) & 0x3F);
	if ((context->count[0] += ((UINT4)inputLen << 3))
		< ((UINT4)inputLen << 3))
		context->count[1]++;
	context->count[1] += ((UINT4)inputLen >> 29);

	partLen = 64 - index;

	if (inputLen >= partLen) {
		memcpy((POINTER)&context->buffer[index], (POINTER)input, partLen);
		MD5Transform(context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
			MD5Transform(context->state, &input[i]);
		index = 0;
	}
	else
		i = 0;

	memcpy((POINTER)&context->buffer[index], (POINTER)&input[i], inputLen - i);
}

inline  void  MD5Final(unsigned  char  digest[16], MD5_CTX  *context)
{
	unsigned  char  bits[8];
	unsigned  int  index, padLen;

	Encode(bits, context->count, 8);
	index = (unsigned  int)((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MD5Update(context, PADDING, padLen);
	MD5Update(context, bits, 8);
	Encode(digest, context->state, 16);
	memset((POINTER)context, 0, sizeof(*context));
}

void  MD5Digest(char  *pszInput, unsigned  long  nInputSize, char  *pszOutPut)
{
	MD5_CTX  context;
	unsigned  int  len = strlen(pszInput);

	MD5Init(&context);
	MD5Update(&context, (unsigned  char  *)pszInput, len);
	MD5Final((unsigned  char  *)pszOutPut, &context);
}

#pragma endregion

#pragma region BASE64ת��

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";
std::string base64_encode(char* bytes_to_encode, unsigned int in_len) {
	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i < 4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';

	}

	return ret;

}
#pragma endregion
#pragma region �Զ��巽��

vector<string> v;
char c_spliter = '|';
void SplitStr(char* input, char* spliter, vector<char*>& output)
{
	char *p;
	p = strtok(input, spliter);
	while (p)
	{
		output.push_back(p);
		p = strtok(NULL, spliter);
	}
}
int my_split(const std::string& src, const char& delim,
	std::vector<std::string>& vec)
{
	int src_len = src.length();
	int find_cursor = 0;
	int read_cursor = 0;

	if (src_len <= 0) return -1;

	vec.clear();
	while (read_cursor < src_len) {

		find_cursor = src.find(delim, find_cursor);

		//1.�Ҳ����ָ���
		if (-1 == find_cursor) {
			if (read_cursor <= 0) return -1;

			//���һ���Ӵ�, src��βû�зָ���
			if (read_cursor < src_len) {
				vec.push_back(src.substr(read_cursor, src_len - read_cursor));
				return 0;
			}
		}
		//2.�������ָ��������
		else if (find_cursor == read_cursor) {
			//�ַ�����ͷΪ�ָ���, Ҳ�����Ӵ�����, �粻��Ҫ�ɼ����ж�&&(read_cursor!=0)
			vec.push_back(std::string(""));
		}
		//3.�ҵ��ָ���
		else
			vec.push_back(src.substr(read_cursor, find_cursor - read_cursor));

		read_cursor = ++find_cursor;
		if (read_cursor == src_len) {
			//�ַ����Էָ�����β, �粻��Ҫĩβ���Ӵ�, ֱ��return
			vec.push_back(std::string(""));
			return 0;
		}
	}//end while()

	return 0;
}
void TransScanMode() //�������������Ϊָ��ɨ��ģʽ
{
	/*HMODULE hdll = LoadLibraryA(CONDLL);*/
	if (HIns_WQ == NULL)
	{
		return;
	}
	else
	{
		getscanmod scanmod = (getscanmod)GetProcAddress(HIns_WQ, "GetScanMode");
		char inputdata[1024] = { 0 };
		char errmsg[1024] = { 0 };
		int ret = scanmod(inputdata, errmsg);
		if (ret == 0)
		{
			if (strcmp(inputdata, "00") == 0)
			{
				checkmodcmd ckcmd = (checkmodcmd)GetProcAddress(HIns_WQ, "Checkmod_Cmd");
				ckcmd(inputdata, errmsg);
				return;
			}
			else
			{
				return;
			}
		}
		else
		{
			return;
		}
	}
}
string TransDate(char* jydt)
{
	std::string str_dt(jydt);
	std::string str_trunce;
	while (str_dt.find("-") != -1)
	{
		str_trunce = str_dt.replace(str_dt.find("-"), 1, "");
	}
	while (str_dt.find(":") != -1)
	{
		str_trunce = str_dt.replace(str_dt.find(":"), 1, "");
	}
	while (str_dt.find(" ") != -1)
	{
		str_trunce = str_dt.replace(str_dt.find(" "), 1, "");
	}
	return str_trunce;
}
///����������ȡIP
BOOL GetIpByDomainName(char *szHost, char* szIp)
{
	WSADATA        wsaData;

	HOSTENT   *pHostEnt;
	int             nAdapter = 0;
	struct       sockaddr_in   sAddr;
	if (WSAStartup(0x0101, &wsaData))
	{
		//printf(" gethostbyname error for host:\n");
		return FALSE;
	}

	pHostEnt = gethostbyname(szHost);
	if (pHostEnt)
	{
		if (pHostEnt->h_addr_list[nAdapter])
		{
			memcpy(&sAddr.sin_addr.s_addr, pHostEnt->h_addr_list[nAdapter], pHostEnt->h_length);
			sprintf(szIp, "%s", inet_ntoa(sAddr.sin_addr));
		}
	}
	else
	{
		//      DWORD  dwError = GetLastError();
		//      CString  csError;
		//      csError.Format("%d", dwError);
	}
	WSACleanup();
	return TRUE;
}
//д��̶�Ŀ¼��־
void W_log(const char* str)
{
	char* dir_path = "./Log";
	if (_access("./Log", 0) == -1)
	{
		_mkdir("./Log");
	}
	char log_name[128];
	char shijian[24];
	time_t t = time(0);
	strftime(log_name, sizeof(log_name), "./Log//%Y%m%d.log", localtime(&t));
	strftime(shijian, sizeof(shijian), "%Y-%m-%d %H:%M:%S", localtime(&t));

	ofstream fin;
	fin.open(log_name, std::ios::app);
	char HeadLine[128] = { 0 };
	sprintf(HeadLine, "################################%s --Begin################################", shijian);
	fin << shijian << ":\t" << str << endl;
	fin.close();
}
//д�������־
void W_ReadCardLog(const char* str)
{
	char* dir_path = "./Log";
	if (_access("./Log", 0) == -1)
	{
		_mkdir("./Log");
	}
	char log_name[128];
	char cur_time[24];
	time_t t = time(0);
	strftime(log_name, sizeof(log_name), "./Log/ReadCard%Y%m%d.log", localtime(&t));
	strftime(cur_time, sizeof(cur_time), "%Y-%m-%d %H:%M:%S", localtime(&t));
	ofstream fin;
	fin.open(log_name, std::ios::app);
	fin << cur_time << "\t" << str << endl;
	fin.close();
}
void W_UploadLog(const char* str)
{
	char* dir_path = "./Log//Upload";
	if (_access(dir_path, 0) == -1)
	{
		_mkdir(dir_path);
	}
	char log_name[128];
	char shijian[24];
	time_t t = time(0);
	strftime(log_name, sizeof(log_name), "./Log//Upload//%Y%m%d.log", localtime(&t));
	strftime(shijian, sizeof(shijian), "%Y-%m-%d %H:%M:%S", localtime(&t));

	ofstream fin;
	fin.open(log_name, std::ios::app);
	char HeadLine[128] = { 0 };
	sprintf(HeadLine, "################################%s --Begin################################", shijian);
	fin << HeadLine << "\r\n" << str << endl;
	fin.close();
}
//д���ı���filename���ı�·��+�ļ���,str_to_write����Ҫд�������
void WriteInFile(char* filename, std::string str_to_write)
{
	std::ofstream fout(filename, std::ios::app);
	fout << str_to_write.c_str();
	fout.close();
}

//string encrypt(const string& plainText)
//{
//	string cipherText;
//	CryptoPP::AES::Encryption aesEncryption(s_key, CryptoPP::AES::DEFAULT_KEYLENGTH);
//	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, s_iv);
//	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipherText));
//	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.length());
//	stfEncryptor.MessageEnd();
//
//	string cipherTextHex;
//	for (int i = 0; i < cipherText.size(); i++)
//	{
//		char ch[3] = { 0 };
//		sprintf(ch, "%02x", static_cast<BYTE>(cipherText[i]));
//		cipherTextHex += ch;
//	}
//	return cipherTextHex;
//}
//string decrypt(string cipherTextHex)
//{
//	string cipherText;
//	string decryptedText;
//
//	int i = 0;
//	while (true)
//	{
//		char c;
//		int x;
//		stringstream ss;
//		ss << hex << cipherTextHex.substr(i, 2).c_str();
//		ss >> x;
//		c = (char)x;
//		cipherText += c;
//		if (i >= cipherTextHex.length() - 2)break;
//		i += 2;
//	}
//
//	//  
//	CryptoPP::AES::Decryption aesDecryption(s_key, CryptoPP::AES::DEFAULT_KEYLENGTH);
//	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, s_iv);
//	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedText));
//	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(cipherText.c_str()), cipherText.size());
//
//	stfDecryptor.MessageEnd();
//
//	return decryptedText;
//}
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
	//W_ReadCardLog("EVENT ���ú���GetBlackList��ʼ");
	char _log[64] = { 0 };
	sprintf(_log, "PARA UID:%ld", uid);
	//W_ReadCardLog(_log);
	const int BUF_SIZE = 64;
	WSADATA         wsd;            //WSADATA����  
	SOCKET          sHost;          //�������׽���  
	SOCKADDR_IN     servAddr;       //��������ַ  
	char            buf[BUF_SIZE];  //�������ݻ�����  
	int             retVal;         //����ֵ  
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		//W_ReadCardLog("ERROR -1 WSA����ʧ��");
		return -1;		//WSA����ʧ��
	}
	sHost = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == sHost)
	{
		//W_ReadCardLog("ERROR -2 socket failed");
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
		//W_ReadCardLog("ERROR -3 ����ʧ��");
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
		//W_ReadCardLog("ERROR -4 ����ʧ��");
		closesocket(sHost);
		WSACleanup();
		return -4;		//����ʧ��
	}
	char* recvbuf = recv_buf;
	recv(sHost, recvbuf, 1, 0);
	closesocket(sHost); //�ر��׽���  
	WSACleanup();       //�ͷ��׽�����Դ  
	//W_ReadCardLog("INFO socket��֤���");
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
long SendPostRequest(const char *ip, short port, char *bufSend, char *recv_buf)
{
	//W_ReadCardLog("EVENT ���ú���SendPostRequest��ʼ");
	const int BUF_SIZE = 64;
	WSADATA         wsd;            //WSADATA����  
	SOCKET          sHost;          //�������׽���  
	SOCKADDR_IN     servAddr;       //��������ַ  
	char            buf[BUF_SIZE];  //�������ݻ�����  
	int             retVal;         //����ֵ  
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		//W_ReadCardLog("ERROR -1 WSA����ʧ��");
		return -1;		//WSA����ʧ��
	}
	sHost = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == sHost)
	{
		//W_ReadCardLog("ERROR -2 socket failed");

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
		//W_ReadCardLog("ERROR -3 ����ʧ��");
		closesocket(sHost);
		WSACleanup();
		return -3;		//����ʧ��
	}
	//���������������
	ZeroMemory(buf, BUF_SIZE);
	retVal = send(sHost, bufSend, strlen(bufSend), 0);
	string str = bufSend;
	if (SOCKET_ERROR == retVal)
	{
		//W_ReadCardLog("ERROR -4 ����ʧ��");
		closesocket(sHost);
		WSACleanup();
		return -4;		//����ʧ��
	}
	char* recvbuf = recv_buf;
	recv(sHost, recvbuf, 1024, 0);
	closesocket(sHost); //�ر��׽���  
	WSACleanup();       //�ͷ��׽�����Դ  
	return  0;
}

//��ȡ�����ļ�IP��ַ
LPSTR _stdcall GetIPAddrINI()
{
	LPSTR ipaddr = new char[20];
	GetPrivateProfileStringA("SERVER", "IPADDR", "NULL", ipaddr, 20, iniFileName);
	return ipaddr;
}
//��ȡ�����ļ�port
short  GetPortINI()
{
	LPSTR LP_PATH = new char[MAX_PATH];
	short port;
	port = GetPrivateProfileIntA("SERVER", "PORT", 80, iniFileName);
	return port;
}

//ͨ��UID��֤������
long VerifiBlackCard_UID(long u_id)
{

	const char* ipaddr = GetIPAddrINI();
	short port = GetPortINI();
	char recv_buf = '9';
	long status = GetBlackList(ipaddr, port, u_id, &recv_buf);
	//W_ReadCardLog("EVENT ���ú���GetBlackList����");
	if (status == 0)
	{
		if (recv_buf == '1')
		{
			return -777;
		}
		else if (recv_buf == '0')
		{
			return 0;
		}
		else
		{
			return -700;
		}
	}
	else
	{
		return -600;
	}
	//ȡ����֤������ʧ��ʱ�Ķ����֤����
	//if (status == 0)
	//{
	//	//socket����ֵΪ1����ʾ�˿�UID�ں���������
	//	if (recv_buf == '1')
	//	{
	//		is_black = -1;
	//		return 463;
	//	}
	//	//socket����ֵΪ2����ʾ�ӿڷ����쳣������������
	//	if (recv_buf == '2')
	//	{
	//		int i = 0;
	//		int max_count = 2;
	//		while ((recv_buf == '2') && (i < max_count))
	//		{
	//			GetBlackList(ipaddr, port, u_id, &recv_buf);
	//			i++;
	//		}
	//		switch (recv_buf)
	//		{
	//		case '2':
	//			is_black = 0;
	//			return 404;
	//			break;
	//		case '1':
	//			is_black = -1;
	//			return 463;
	//			break;
	//		case '0':
	//			is_black = 1;
	//			return 0;
	//			break;
	//		default:
	//			return 51;
	//			break;
	//		}
	//	}
	//	else
	//	{
	//		is_black = 1;
	//		return 0;
	//	}
	//}

	//else
	//{
	//	return 404;					//��������֤�ӿ������쳣
	//}
}
void TransCharacter(const char* input, char* output)
{
	int _wcsLen = ::MultiByteToWideChar(CP_UTF8, NULL, input, strlen(input), NULL, 0);
	wchar_t* _wszString = new wchar_t[_wcsLen + 1];
	//ת��
	::MultiByteToWideChar(CP_UTF8, NULL, input, strlen(input), _wszString, _wcsLen);
	//������'\0'
	_wszString[_wcsLen] = '\0';
	_bstr_t _b(_wszString);
	strcpy(output, _b);
}
//ͨ�������ļ���ȡ�ֶε�ֵ
LPSTR GetValueInIni(char* className, char* objName, LPCSTR fileName)
{
	LPSTR LP_PATH = new char[MAX_PATH];
	LPSTR rt_Value = new char[128];
	strcpy(LP_PATH, fileName);
	GetPrivateProfileStringA(className, objName, "NULL", rt_Value, 128, LP_PATH);
	delete[] LP_PATH;
	return rt_Value;
}
//���ݹ������hashֵ
LPSTR _stdcall GetHash(char* appID, char* random, char* timestamp, char* hx_key)
{
	char _md5jiegou[16];
	/*char *x_key = hx_key;
	char *ppid = appID;
	char *andom = random;
	char *a_ts = timestamp;*/
	char sr[64];
	sprintf(sr, "%s%s%s%s", appID, timestamp, random, hx_key);
	MD5Digest(sr, strlen(sr), _md5jiegou);
	std::string a_hash = base64_encode(_md5jiegou, 16);
	return (char*)a_hash.data();
}
//post�ϴ����Ѽ�¼
long UploadDetailByPost(char* http_req, char* host, char* url)
{
	//W_ReadCardLog("EVENT ���ú���UploadDetailByPost��ʼ");
	int _appid = GetPrivateProfileIntA("TransDetail", "appID", -1, iniFileName); //41;
	int _apptypeid = GetPrivateProfileIntA("TransDetail", "appTypeID", -1, iniFileName); //11;
	char *ip = GetValueInIni("TransDetail", "IP", iniFileName); //"192.168.10.205";
	char *hxKey = GetValueInIni("TransDetail", "key", iniFileName);
	//����hashֵ
	char md5jiegou[16];
	char *random = "1";
	SYSTEMTIME _st = { 0 };
	GetLocalTime(&_st);
	char ts[15];
	sprintf(ts, "%d%02d%02d%02d%02d%02d", _st.wYear, _st.wMonth, _st.wDay, _st.wHour, _st.wMinute, _st.wSecond);
	char shuru[64];
	sprintf(shuru, "%d%s%s%s", _appid, ts, random, hxKey);
	MD5Digest(shuru, strlen(shuru), md5jiegou);
	std::string hash = base64_encode(md5jiegou, 16);
	//hash�������
	Json::Value req;
	req["posCode"] = GetValueInIni("TransDetail", "posCode", iniFileName);//"090001000004";
	req["merchantNo"] = GetValueInIni("TransDetail", "MerchantNo", iniFileName);//"09000001";
	req["TestFlag"] = GetValueInIni("TransDetail", "TestFlag", iniFileName);//���Լ�¼����ʽ��¼��ĳ�1
	req["Collectdt"] = ts;
	//���в����ǹ̶�ֵ
	req["TradeCityCode"] = "0374";
	req["OwneityCode"] = "4610";
	req["AssCardType"] = 1;
	req["TradeKind"] = "-1";
	req["eCode"] = "08600000001";
	req["WalletType"] = 0;
	req["BatchNo"] = "0";
	req["OperatorID"] = "0";
	req["CardClass"] = 2;
	req["FavouredFare"] = 0;
	req["TradeAppType"] = 0;
	req["MainCardType"] = 0;
	req["AssCardType"] = 1;
	req["CardVersion"] = 0;
	req["UserDefinedType"] = 0;
	req["UnionPoscode"] = "";
	req["UnionMerchantcode"] = "";
	req["UnionCardno"] = "";
	req["UnionExt"] = "";
	req["CustomExt1"] = "";
	req["CustomExt2"] = "";
	req["doubleUpload"] = 0;
	req["planID"] = 0;
	req["saveOpCount"] = 0;
	//��������json
	std::string str_req(http_req);
	Json::Value root;
	Json::Reader reader;
	if (reader.parse(str_req, root))
	{
		req["samCardNo"] = root["psamId"];
		req["TAC"] = root["TAC"];
		req["SAMTradeNo"] = root["psamJyNo"];
		req["OpDateTime"] = root["opDatetime"];
		req["OpFare"] = root["opfare"];
		req["Oddfare"] = root["Oddfare"];
		req["CardNo"] = root["CardNo"];
		req["CustomerId"] = root["CustomerId"];
		req["OpCount"] = root["OpCount"];
		//�Ӽ�¼��ȡ���׼�¼��ˮ��
		//�����¼��û��TradeRecNo�ļ�ֵ������0
		if (root["TradeRecNo"])
		{
			req["TradeRecNo"] = root["TradeRecNo"];
		}
		else
		{
			req["TradeRecNo"] = 0;
		}
		req["id"] = req["TradeRecNo"];
		//����׼��������ֶ�Ret����ʾ�ۿ�״̬ 2018-11-01 14:32:23
		req["Ret"] = root["Ret"];
	}
	string req_to_str = req.toStyledString();

	char buf_Send[2048];
	sprintf(buf_Send,
		"POST %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Cache-Control: no-cache\r\n"
		"Connection:Keep-Alive\r\n"
		"Accept-Encoding:gzip, deflate\r\n"
		"Accept-Language:zh-CN,en,*\r\n"
		"Content-Length:%d\r\n"
		"ver: 2.0\r\n"
		"appid: %d\r\n"
		"apptypeid: %d\r\n"
		"timestamp: %s\r\n"
		"hash: %s\r\n"
		"random: 1\r\n"
		"ip:%s\r\n"
		"Content-Type:application/json\r\n\r\n"
		"%s", url, host, req_to_str.length(), _appid, _apptypeid, ts, hash.c_str(), ip, req_to_str.c_str()
	);
	//W_ReadCardLog("INFO ���ϴ�����json�������");
	char req_resv[1024];
	char req_ip[24];
	GetIpByDomainName(host, req_ip);
	//2018-09-07 12:19	�˴��޸�Ϊ���ύpost֮ǰ����Ϣд���ύ��־��������������־���յ������д��
	W_UploadLog(buf_Send);
	short _port = GetPrivateProfileIntA("TransDetail", "PORT", 80, iniFileName);

	//�ύPOST
	long ret_sendpost = SendPostRequest(req_ip, _port, buf_Send, req_resv);
	char sendlog[64] = { 0 };
	sprintf(sendlog, "EVENT ���ú���SendPostRequest����,POST�����ύ���,����%ld", ret_sendpost);
	//W_ReadCardLog(sendlog);
	if (0 == ret_sendpost)
	{
		//��������
		int _wcsLen = ::MultiByteToWideChar(CP_UTF8, NULL, req_resv, strlen(req_resv), NULL, 0);
		//����ռ�Ҫ��'\0'�����ռ䣬MultiByteToWideChar�����'\0'�ռ�
		wchar_t* _wszString = new wchar_t[_wcsLen + 1];
		//ת��
		::MultiByteToWideChar(CP_UTF8, NULL, req_resv, strlen(req_resv), _wszString, _wcsLen);
		//������'\0'
		_wszString[_wcsLen] = '\0';
		_bstr_t _b(_wszString);
		char *_rev_temp = _b;
		//��ȡjson
		string str_rev(_rev_temp);
		string json_rel;
		int json_bg = str_rev.find_first_of("{", 0);
		int json_end = str_rev.find_last_of("}");
		if (json_end > json_bg)
		{
			json_rel = str_rev.substr(json_bg, json_end - json_bg + 1);
			//д���ϴ���־
			/*string str_send(buf_Send);
			string str_log = str_send + json_rel;
			W_UploadLog(str_log.c_str());*/
			//ͬ�ϣ�ע�͵�������룬�˴��޸�Ϊ������������Ϣ����д��
			W_UploadLog(json_rel.c_str());
			//����json
			Json::Value js_vl;
			Json::Reader reader;
			if (reader.parse(json_rel, js_vl))
			{
				if (js_vl["outMsg"].asString() == "������ϸ�ϴ�����")
				{
					//W_ReadCardLog("INFO ������ϸ�ϴ�����");
					return 0;
				}
				else
				{
					//W_ReadCardLog("ERROR ������ϸ�ϴ��쳣");
					return -11;
				}
			}
		}
		else
		{
			//W_ReadCardLog("ERROR �ϴ��ӿڷ�����Ϣ��ʽ����");
			return -12;
		}
	}
	else
	{
		return ret_sendpost;
	}


}
//�ļ������ʹ���Ŀǰֻ�������ĵ���
void OpFile()
{
	//W_ReadCardLog("EVENT ���ú���OpFile��ʼ");
	SYSTEMTIME st = { 0 };
	GetLocalTime(&st);
	char filename[64] = { 0 };
	sprintf(filename, ".//Log//Pre//Pre_%d%02d%02d.dat", st.wYear, st.wMonth, st.wDay);
	//������ʱ�ļ�
	ofstream outf("temp_comp.txt", ios::out | ios::trunc);
	ofstream unload_file("temp_unload.txt", ios::out | ios::trunc);

	LPSTR HOST = GetValueInIni("TransDetail", "HOST", iniFileName);	//�����ϴ�����
	LPSTR URL = GetValueInIni("TransDetail", "URL", iniFileName);	//�����ϴ���ַ
	char _log[256] = { 0 };
	sprintf(_log, "EVENT �������ļ���ȡ����,HOST:%s,URL:%s", HOST, URL);
	//W_ReadCardLog(_log);
	//��Ԥ�ϴ��ı��ļ�
	char buffer[1024] = { 0 };
	std::ifstream fin;
	fin.open(filename, std::ios::in);
	while (!fin.eof())
	{
		fin.getline(buffer, 1024, '\n');
		int size = strlen(buffer);

		if (size > 2)
		{
			Json::Reader reader;
			Json::Value root;
			reader.parse(buffer, root, true);
			int upload_st = root["Upload"].asInt();
			if (upload_st == 0)
			{
				//�����ϴ�����
				long ret = UploadDetailByPost(buffer, HOST, URL);
				//W_ReadCardLog("EVENT ���ú���UploadDetailByPost����");
				if (ret == 0)
				{
					//���ϴ���¼д����ʱ�ļ�
					outf << buffer << endl;
				}
				else
				{
					//δ�ϴ��ɹ���¼д����ʱ�ļ�
					unload_file << buffer << endl;
				}
			}
		}
	}
	fin.close();
	outf.close();
	unload_file.close();
	//���ύ��¼�ļ�·��
	const char* comp_path = "./Log//Comp";
	if (_access(comp_path, 0) == -1)
	{
		_mkdir(comp_path);
	}
	char uped_file[64] = { 0 };
	sprintf(uped_file, "./Log//Comp//Comp_%d%02d%02d.dat", st.wYear, st.wMonth, st.wDay);
	ofstream comp_f(uped_file, ios::out | ios::app);
	ifstream f_temp_comp;
	f_temp_comp.open("temp_comp.txt", std::ios::in);
	char buff_comp[1024] = { 0 };
	while (!f_temp_comp.eof())
	{
		f_temp_comp.getline(buff_comp, 1024, '\n');
		if (strlen(buff_comp) > 2)
		{
			comp_f << buff_comp << endl;
		}
	}
	comp_f.close();
	f_temp_comp.close();
	//�޸�Pre�ļ�
	ofstream f_prefile;
	f_prefile.open(filename, ios::out | ios::trunc);
	ifstream f_temp_uload;
	f_temp_uload.open("temp_unload.txt", ios::in);
	char buff_uload[1024] = { 0 };
	while (!f_temp_uload.eof())
	{
		f_temp_uload.getline(buff_uload, 1024, '\n');
		if (strlen(buff_uload) > 2)
		{
			f_prefile << buff_uload << endl;
		}
	}
	f_temp_uload.close();
	f_prefile.close();
	remove("temp_comp.txt");
	remove("temp_unload.txt");
	//W_ReadCardLog("INFO ɾ����Ŀ¼��ʱ�ļ�");
}
///
/* �˷������ױ���δ֪���ϣ���ʱע�͵� 
void JudgeHDDType()
{
	W_ReadCardLog("EVENT JudgeHDDType START");

	opCom open_com;
	open_com = (opCom)GetProcAddress(HIns_CAP, "OpenCom");

	long ret1 = open_com();
	char log[100];
	if (ret1 == 0)
	{
		HDDTYPE = 1;
		W_ReadCardLog("TYPE 1");
		return;
	}
	else
	{

		readcardinfo ef05 = (readcardinfo)GetProcAddress(HIns_WQ, "ReadCardInfo");

		if (ef05 == NULL)
		{
			//FreeLibrary(hdll2);
			W_ReadCardLog("ERROR JudgeHDDType ����ReadCardInfo����ʧ��");
			HDDTYPE = -1;
			return;
		}
		else
		{
			HDDTYPE = 2;
			W_ReadCardLog("TYPE 2");
			return;
		}
	}
}
*/
//��ȡɨ��ǹ���ں�
short WINAPI GetSERIALPORT()
{
	short port;
	port = GetPrivateProfileIntA("SCNNER", "SERIALPORT", -1, iniFileName);
	return port;
}
int DC_SCAN(char* scandata)
{
	//HMODULE HINS_DC = LoadLibraryA("dcrf32.dll");
	char log[100];

	dcinit init = (dcinit)GetProcAddress(HIns_DC, "dc_init");
	HANDLE dev = init(100, 9600);
	sprintf(log, "�豸�����%ld", (long)dev);
	W_ReadCardLog(log);
	if ((long)dev>0)
	{
		W_ReadCardLog("DC init success");
	}
	dc_startscan sscan = (dc_startscan)GetProcAddress(HIns_DC, "dc_Scan2DBarcodeStart");
	unsigned char _mode = '0x00';
	int ret = sscan(dev, _mode);
	sprintf(log, "start scan status��%d", ret);
	W_ReadCardLog(log);
	dc_getscandata getdata = (dc_getscandata)GetProcAddress(HIns_DC, "dc_Scan2DBarcodeGetData");
	int rlen = 0;
	unsigned char buffer[512] = { 0 };
	ret = getdata(dev, &rlen, buffer);
	dc_sacnexit scanexit = (dc_sacnexit)GetProcAddress(HIns_DC, "dc_Scan2DBarcodeExit");
	int i = 0;
	int maxtime = 30;
	while ((strlen((const char*)buffer) == 0) && (i<maxtime))
	{
		i++;
		Sleep(100);
		ret = getdata(dev, &rlen, buffer);
	}
	strcpy(scandata, (const char*)buffer);
	sprintf(log, "DC_SCAN��ȡ��ά�룺%s��״̬��%d,scandata:%s", buffer, ret, scandata);
	W_ReadCardLog(log);
	ret = scanexit(dev);
	dc_exit dcexit = (dc_exit)GetProcAddress(HIns_DC, "dc_exit");
	ret = dcexit(dev);
	return ret;
}
//�����豸���ͷ���ɨ����ֵ
long WINAPI GetComInputInfo(LPSTR info)
{
	W_ReadCardLog("EVENT GetComInputInfo START");
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	//JudgeHDDType();
	if ((HDDTYPE == 0)||(HDDTYPE==3))
	{
		CSerial cs;
		short sPort = 0;

		short serial_port = GetSERIALPORT();
		if ((serial_port == 0) || (serial_port == -1))
		{
			//�Զ�ʶ�𴮿ں�
			for (int i = 1; i < 10; i++)
			{
				bool isOpen = cs.Open(i);
				if (isOpen)
				{
					sPort = i;
					cs.Close();
				}
			}
		}
		else
		{
			sPort = serial_port;
		}
		char log1[100] = { 0 };
		sprintf(log1, "�Զ�ʶ��˿ں�Ϊ��%d", sPort);
		W_ReadCardLog(log1);
		bool bs = cs.Open(sPort);
		char rev[1024] = { 0 };
		DWORD T = 0;
		DWORD TOTAL = 20000;
		long ret = 0;
		while (T < TOTAL)
		{
			char *p = strchr(rev, '\r');
			if (p)
			{
				ret = 0;
				break;
			}
			else
			{
				Sleep(500);
				cs.ReadData(rev, 1024);
				T += 500;
				ret = -1;
			}

		}
		cs.Close();
		string str_input(rev);
		int len_r = str_input.find_first_of("\r", 0);
		string str_finnal = str_input.substr(0, len_r);
		strcpy(info, str_finnal.c_str());
		char log[100] = { 0 };
		sprintf(log, "�´�½ɨ�뷵�أ�%d����ֵ��%s", ret, info);
		W_ReadCardLog(log);
		return ret;
	}
	if (HDDTYPE==1)
	{
		int ret = DC_SCAN(info);
		return ret;
	}
	if (HDDTYPE == 2)
	{
		TransScanMode();//�ı�ɨ��ģʽ
		/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
		if (HIns_WQ == NULL)
		{
			return -1801;
		}
		else
		{
			sendscancmd scan = (sendscancmd)GetProcAddress(HIns_WQ, "SendScanCmd");
			char errmsg[1024] = { 0 };
			int ret = scan(info, errmsg);
			char log[100] = { 0 };
			sprintf(log, "����ɨ����ֵ��%s,ɨ��״̬��%d", info,ret);
			W_ReadCardLog(log);
			//2019��12��12��10:57:26 ���ӳ�ʱ������102
			if (-11 == ret)
			{
				return OUTTIME;
			}
			return ret;
		}
	}
	else
	{
		return COMMONERROR;
	}

}

//ͨ���������ά���ȡ������Ϣ //ʵ�忨��type=1 //���ӿ���type=2
long GetCusInfoByUnion(long type, char* inputMsg, char* outMsg)
{
	W_ReadCardLog("EVENT GetCusInfoByUnion START");
	string content;
	string searchtype;
	//��ȷ��֧����ʽ
	if (type == 1)//ʵ�忨
	{
		string content_kh(inputMsg);
		content = content_kh;
		searchtype = "searchIdCard";

	}
	if (type == 2)//���ӿ�
	{
		string content_qrcode(inputMsg);
		content = content_qrcode;
		searchtype = "search";
	}
	//
	char req_resv[2048];
	LPSTR req_ip;
	req_ip = GetValueInIni("MIS", "BCNIP", iniFileName);
	short _port = GetPrivateProfileIntA("MIS", "BCNPORT", 80, iniFileName);
	char log[100];
	sprintf(log, "ip��%s,port:%d", req_ip, _port);
	W_ReadCardLog(log);
	//���岢��ʼ��Json����
	Json::Value sendvalue;
	//string content(_info);
	string orgcode(GetValueInIni("MIS", "ORGCODE", iniFileName));
	string serialNo(GetValueInIni("MIS", "SERIALNO", iniFileName));
	sendvalue["content"] = content;
	sendvalue["organizationCode"] = orgcode;
	sendvalue["serialNumber"] = serialNo;
	sendvalue["method"] = searchtype;
	sendvalue["dataType"] = "010115";
	string sendJson = sendvalue.toStyledString();
	char _send_buff[2048] = { 0 };
	strcpy(_send_buff, sendJson.c_str());
	char logtmp[2048];
	sprintf(logtmp, "�������������Ϊ�� %s", _send_buff);
	W_ReadCardLog(logtmp);
	//��������
	long ret_sendpost = SendPostRequest(req_ip, _port, _send_buff, req_resv);
	char log1[1000];
	sprintf(log1, "POST����%d,respons:%s", ret_sendpost,req_resv);
	W_ReadCardLog(log1);
	if (0 == ret_sendpost)
	{
		char _rev_temp[2048] = { 0 };
		TransCharacter(req_resv, _rev_temp);
		//��ȡjson
		string str_rev(_rev_temp);
		string json_rel;
		int json_bg = str_rev.find_first_of("{", 0);
		int json_end = str_rev.find_last_of("}");
		if (json_end > json_bg)
		{
			json_rel = str_rev.substr(json_bg, json_end - json_bg + 1);
			W_ReadCardLog(json_rel.c_str());
			strcpy(outMsg, json_rel.c_str());
			return 0;
		}
		else
		{
			return 103;
		}
	}
	else
	{
		return 404;
	}
}

//ͨ���������ά���ȡ������Ϣ //ʵ�忨��type=1 //���ӿ���type=2
long GetCusInfoByUnion_DataType(long type, char* inputMsg,char* datatype, char* outMsg)
{
	W_ReadCardLog("EVENT GetCusInfoByUnion START");
	string content;
	string searchtype;
	string str_datatype(datatype);
	//��ȷ��֧����ʽ
	if (type == 1)//ʵ�忨
	{
		string content_kh(inputMsg);
		content = content_kh;
		searchtype = "searchIdCard";

	}
	if (type == 2)//���ӿ�
	{
		string content_qrcode(inputMsg);
		content = content_qrcode;
		searchtype = "search";
	}
	//
	char req_resv[2048];
	LPSTR req_ip;
	req_ip = GetValueInIni("MIS", "BCNIP", iniFileName);
	short _port = GetPrivateProfileIntA("MIS", "BCNPORT", 80, iniFileName);
	char log[100];
	sprintf(log, "ip��%s,port:%d", req_ip, _port);
	W_ReadCardLog(log);
	//���岢��ʼ��Json����
	Json::Value sendvalue;
	Json::Reader reader;
	Json::Value dp;
	reader.parse(datatype, dp);

	//string content(_info);
	string orgcode(GetValueInIni("MIS", "ORGCODE", iniFileName));
	string serialNo(GetValueInIni("MIS", "SERIALNO", iniFileName));
	sendvalue["content"] = content;
	sendvalue["organizationCode"] = orgcode;
	sendvalue["serialNumber"] = serialNo;
	sendvalue["method"] = searchtype;
	sendvalue["dataType"]["medSectionCode"] = dp["medSectionCode"];
	sendvalue["dataType"]["medStepCode"] = dp["medStepCode"];

	string sendJson = sendvalue.toStyledString();
	char _send_buff[2048] = { 0 };
	strcpy(_send_buff, sendJson.c_str());
	char logtmp[2048];
	sprintf(logtmp, "�������������Ϊ�� %s", _send_buff);
	W_ReadCardLog(logtmp);
	//��������
	long ret_sendpost = SendPostRequest(req_ip, _port, _send_buff, req_resv);
	char log1[1000];
	sprintf(log1, "POST����%d,respons:%s", ret_sendpost, req_resv);
	W_ReadCardLog(log1);
	if (0 == ret_sendpost)
	{
		char _rev_temp[2048] = { 0 };
		//TransCharacter(req_resv, _rev_temp);
		//��ȡjson
		string str_rev(req_resv);
		string json_rel;
		int json_bg = str_rev.find_first_of("{", 0);
		int json_end = str_rev.find_last_of("}");
		if (json_end > json_bg)
		{
			json_rel = str_rev.substr(json_bg, json_end - json_bg + 1);
			W_ReadCardLog(json_rel.c_str());
			strcpy(outMsg, json_rel.c_str());
			return 0;
		}
		else
		{
			return 103;
		}
	}
	else
	{
		return 404;
	}
}
#pragma endregion

#pragma region ����ͨ�ӿ�

//������

long _stdcall OpenCom()
{
	W_ReadCardLog("EVENT OpenCom START");
	string testpath = ".\\ChgCity.ini";
	FILE *fp = fopen(testpath.data(), "r");
	if (!fp)
	{
		strcpy(iniFileName, "D:\\ChgCity.ini");
	}
	else
	{
		strcpy(iniFileName, testpath.c_str());
	}
	return 0;
}
//�ر�����
void _stdcall CloseCom()
{
	W_ReadCardLog("EVENT CloseCom START");

	return;
}
//��ȡ�û���Ϣ
long _stdcall  CapGetNBCardInfo(CUSTOMERINFO *info)
{
	W_ReadCardLog("EVENT CapGetNBCardInfo START");

	//CUSTOMERINFO custinfo;
	//��ʼ����ͨ��HIS�۷�ǰУ��
	info->Ye = 1000 * 100;
	strcpy(info->CardASN, "17082538");
	info->CardClass = 8;
	const char *name_temp = js_vl["content"]["data"]["userName"].asString().c_str();
	W_ReadCardLog(js_vl.toStyledString().c_str());
	strcpy(info->Name, js_vl["content"]["data"]["userName"].asString().c_str());
	js_vl.clear();
	info->Status = 241;
	return 0;
}
long _stdcall CapNBQueryCard_NoVerify(long *UID)
{
	//W_ReadCardLog("EVENT ���ú���CapNBQueryCard_NoVerify");
	/*HMODULE  hdllInst = LoadLibraryA(CONDLL);*/
	if (HIns_CAP == NULL)
	{
		//W_ReadCardLog("ERROR -1801 Ѱ�����ض�̬��ʧ��");

		return -1801;
	}
	else
	{
		querycard qCard;
		qCard = (querycard)GetProcAddress(HIns_CAP, "CapNBQueryCard");
		if (qCard == NULL)
		{
			//W_ReadCardLog("ERROR -1701 δ���ҵ�CapNBQueryCard�ӿ�");
			return -1701;
		}
		else
		{
			long status_qCard = qCard(UID);
			char _log[64] = { 0 };
			sprintf(_log, "EVENT ���ú���CapNBQueryCard_NoVerify����������%ld", status_qCard);
			//W_ReadCardLog(_log);
			return status_qCard;
		}
	}
}
//Ѱ��
long _stdcall CapNBQueryCard(long *UID)
{
	W_ReadCardLog("EVENT CapNBQueryCard START");

	return 0;
}

//�ۿԭ�ӿ�
long _stdcall CapSetNBCardInfo_Unload(long objNo, long UID, long opFare, LPSTR jyDT, __int64 *psamID, long *psamJyNo, __int64 *tac)
{
	//W_ReadCardLog("EVENT ���ú���CapSetNBCardInfo_Unload");
	char log[128] = { 0 };
	sprintf(log, "PARA objNo:%d,UID:%d,opFare:%d,jyDT:%s", objNo, UID, opFare, jyDT);
	//W_ReadCardLog(log);
	if (is_black != 1)
	{
		//W_ReadCardLog("ERROR -777 �ڿ�");
		return -777;
	}
	else
	{
		/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
		if (HIns_CAP == NULL)
		{
			//W_ReadCardLog("ERROR -1801 Ѱ�����ض�̬��ʧ��");

			return -1801;
		}
		else
		{
			setcardinfo Set_CardInfo = (setcardinfo)GetProcAddress(HIns_CAP, "CapSetNBCardInfo");
			if (Set_CardInfo == NULL)
			{
				//W_ReadCardLog("ERROR -1701 δ���ҵ�CapSetNBCardInfo�ӿ�");
				//FreeLibrary(hdllInst);
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
				__int64* _tac = tac;
				long status_setinfo = Set_CardInfo(_objNo, _UID, _opFare, _jyDT, _psamID, _psamJyNo, _tac);
				__int64 pid = *_psamID;
				long pjyno = *_psamJyNo;
				__int64 tc = *_tac;
				//��¼�ۿ���־

				char _log[256] = { 0 };
				sprintf(_log, "PARA objNO:%ld,UID:%ld,opFare:%ld,jyDT:%s,psamID:%lld,psamJyNo:%ld,tac:%lld;status:%ld", _objNo, _UID, _opFare, _jyDT, pid, pjyno, tc, status_setinfo);
				//W_log(_log);
				//W_ReadCardLog(_log);
				//FreeLibrary(hdllInst);
				return status_setinfo;
			}
		}
	}
}

//�ۿ�,PSAM_IDʹ��LPSTR
long _stdcall  CapSetNBCardInfo_temp(long objNo, long UID, long opFare, LPSTR jyDT, LPSTR psamID, long *psamJyNo, char *tac, int redix)
{
	if (VerifiBlackCard_UID(UID) != 0)
	{
		return -777;
	}
	else
	{
		/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
		if (HIns_CAP == NULL)
		{
			return -1801;
		}
		else
		{
			setcardinfo_str Set_CardInfo = (setcardinfo_str)GetProcAddress(HIns_CAP, "CapSetNBCardInfo_str");
			if (Set_CardInfo == NULL)
			{
				/*FreeLibrary(hdllInst);*/
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
				/*FreeLibrary(hdllInst);*/
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


		/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
		if (HIns_CAP == NULL)
		{
			return -1801;
		}
		else
		{
			setcardinfoLMT Set_CardInfoLMT = (setcardinfoLMT)GetProcAddress(HIns_CAP, "CapSetNBCardInfo_LMT");
			if (Set_CardInfoLMT == NULL)
			{
				//FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{

				long status_setinfoLMT = Set_CardInfoLMT(objNo, UID, opFare, jyDT, onceLmt, dayLmt, psamID, psamJyNo, tac);
				//FreeLibrary(hdllInst);
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

//�۷ѣ��Զ������ϴ�����
long WINAPI CapSetNBCardInfo_Str1_Unload(long objNo, long uid, long opFare, LPSTR jyDT, char *psamID, long *psamJyNo, char *tac, int redix)
{
	//W_ReadCardLog("EVENT ���ú���CapSetNBCardInfo_Str1_Unload");
	char log[128] = { 0 };
	sprintf(log, "PARA objNo:%d,UID:%d,opFare:%d,jyDT:%s", objNo, uid, opFare, jyDT);
	//W_ReadCardLog(log);
	//����UID���к�������֤
	long getblack_status = VerifiBlackCard_UID(uid);
	if (getblack_status != 0)
	{
		//W_ReadCardLog("ERROR -777 �ڿ�");
		return -777;
	}
	else
	{
		/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
		if (HIns_CAP == NULL)
		{
			//W_ReadCardLog("ERROR -1801 Ѱ�����ض�̬��ʧ��");
			return -1801;
		}
		else
		{
			setcardinfo_str1 set_cardstr = (setcardinfo_str1)GetProcAddress(HIns_CAP, "CapSetNBCardInfo_Str1");
			if (set_cardstr == NULL)
			{
				//W_ReadCardLog("ERROR -1701 δ���ҵ�CapSetNBCardInfo_Str1�ӿ�");
				//FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				long status_setcardstr = set_cardstr(objNo, uid, opFare, jyDT, psamID, psamJyNo, tac, redix);
				char* str_jydt = jyDT;
				char* str_psamid = psamID;
				char* str_tac = tac;
				char _log[1024];
				sprintf(_log, "PARA objNO:%ld,UID:%ld,opFare:%ld,jyDT:%s,redix:%d,psamID:%s,psamJyNo:%ld,tac:%s;status:%d", objNo, uid, opFare, str_jydt, redix, str_psamid, *psamJyNo, str_tac, status_setcardstr);
				//W_log(_log);	//ԭ��־���ã����ϵ�./Log/ReadCard.log
				//W_ReadCardLog(_log);
				//FreeLibrary(hdllInst);
				return status_setcardstr;
			}
		}
	}
}
//�۷ѣ����ϴι��ܣ��޺�����У��
long WINAPI CapSetNBCardInfo_SLYY(long objNo, long uid, long opFare, LPSTR jyDT, char *psamID, long *psamJyNo, char *tac, int redix)
{
	//W_ReadCardLog("EVENT ���ú���CapSetNBCardInfo_SLYY��ʼ");
	char log[128] = { 0 };
	sprintf(log, "PARA objNo:%d,UID:%d,opFare:%d,jyDT:%s", objNo, uid, opFare, jyDT);
	//W_ReadCardLog(log);

	/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
	if (HIns_CAP == NULL)
	{
		//W_ReadCardLog("ERROR -1801 Ѱ�����ض�̬��ʧ��");
		return -1801;
	}
	else
	{
		setcardinfo_str1 set_cardstr = (setcardinfo_str1)GetProcAddress(HIns_CAP, "CapSetNBCardInfo_Str1");
		if (set_cardstr == NULL)
		{
			//W_ReadCardLog("ERROR -1701 δ���ҵ�CapSetNBCardInfo_Str1�ӿ�");
			//FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			long status_setcardstr = set_cardstr(objNo, uid, opFare, jyDT, psamID, psamJyNo, tac, redix);
			char* str_jydt = jyDT;
			char* str_psamid = psamID;
			char* str_tac = tac;
			char _log[1024];
			sprintf(_log, "PARA objNO:%ld,UID:%ld,opFare:%ld,jyDT:%s,redix:%d,psamID:%s,psamJyNo:%ld,tac:%s;status:%d", objNo, uid, opFare, str_jydt, redix, str_psamid, psamJyNo, str_tac, status_setcardstr);
			//W_log(_log);	ԭ��־���ã����ϵ�./Log/ReadCard.log
			//W_ReadCardLog(_log);
			//FreeLibrary(hdllInst);
			return status_setcardstr;
		}
	}

}
//5.15.	�ۿpsam���š�TAC�����ַ�����
long WINAPI CapSetNBCardInfo_Str1(long objNo, long uid, long opFare, LPSTR jyDT, char *psamID, long *psamJyNo, char *tac, int redix)
{
	W_ReadCardLog("EVENT CapSetNBCardInfo_Str1 START");
	// JudgeHDDType();
	char outmsg[2048] = { 0 };
	int ret = GetComInputInfo(outmsg);
	if (ret == 0)
	{
		Json::Value sendvalue;
		string orgcode(GetValueInIni("MIS", "ORGCODE", iniFileName));
		string serialNo(GetValueInIni("MIS", "SERIALNO", iniFileName));
		sendvalue["organizationCode"] = orgcode;
		sendvalue["serialNumber"] = serialNo;
		sendvalue["method"] = "pay";
		//ʹ��17λʱ�����Ϊ������
		std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::system_clock::now().time_since_epoch());
		sendvalue["content"]["orderNo"] = ms.count();
		sendvalue["content"]["orderTime"] = TransDate(jyDT);
		sendvalue["content"]["txnAmt"] = opFare;
		sendvalue["content"]["termId"] = atoll(GetValueInIni("MIS", "TERMID", iniFileName));//�ն˺�
		sendvalue["content"]["reqType"] = "��������";
		sendvalue["content"]["couponInfo"] = 0;
		sendvalue["content"]["qrNo"] = outmsg;
		sendvalue["content"]["merId"] = GetValueInIni("MIS", "MERID", iniFileName);
		sendvalue["content"]["merCatCode"] = GetValueInIni("MIS", "MERCATCODE", iniFileName);
		sendvalue["content"]["merName"] = GetValueInIni("MIS", "MERNAME", iniFileName);
		string sendJson = sendvalue.toStyledString();
		char _send_buff[1024] = { 0 };
		memcpy(_send_buff, sendJson.c_str(), 1024);
		W_ReadCardLog(_send_buff);
		//�ύ�ӿ�
		LPSTR req_ip;
		req_ip = GetValueInIni("MIS", "BCNIP", iniFileName);
		short _port = GetPrivateProfileIntA("MIS", "BCNPORT", 80, iniFileName);
		char req_resv[1024] = { 0 };
		long ret_sendpost = SendPostRequest(req_ip, _port, _send_buff, req_resv);
		if (0 == ret_sendpost)
		{
			char _rev_temp[1024] = { 0 };
			TransCharacter(req_resv, _rev_temp);
			//��ȡjson
			string str_rev(_rev_temp);
			string json_rel;
			int json_bg = str_rev.find_first_of("{", 0);
			int json_end = str_rev.find_last_of("}");
			if (json_end > json_bg)
			{
				json_rel = str_rev.substr(json_bg, json_end - json_bg + 1);
				W_ReadCardLog(json_rel.c_str());
				//����Jsonʾ����
				//{"code":"R00000","content":{"data":{"orderNo":"1558334758179","payResult":"�ɹ�","autoCode":"0","termId":"1"}},"desc":"֧���ɹ�","flag":1}
				//����json
				Json::Value root;
				//js_vl.clear();
				Json::Reader reader;
				try
				{
					if (reader.parse(json_rel, root))
					{
						if (root["flag"].asString() == "1")
						{
							W_ReadCardLog("INFO ֧���ɹ�");
							//�������
							strcpy(psamID, GetValueInIni("MIS", "TERMID", iniFileName));
							char tac_temp[20] = { 0 };
							_i64toa(ms.count(), tac_temp, 10);
							strcpy(tac, tac_temp);
							*psamJyNo = atol(root["content"]["data"]["autoCode"].asString().c_str());
							return 0;
						}
						else
						{
							W_ReadCardLog("ERROR ֧��ʧ��");
							return -11;
						}
					}
				}
				catch (const std::exception&ex)
				{
					return -13;
				}
			}
			else
			{
				W_ReadCardLog("ERROR ������Ϣ��ʽ����");
				return -12;
			}
		}
		else
		{
			return ret_sendpost;
		}
	}
	else
	{
		return -1;
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

//5.12.	�ۿTAC�����ַ�����,ԭ�ӿ�
long _stdcall CapSetNBCardInfo_Str_Unload(long objNo, long uid, long opFare, LPSTR jyDT, __int64 *psamID, long *psamJyNo, char *tac, int redix)
{
	//W_ReadCardLog("EVENT ���ú���CapSetNBCardInfo_Str_Unload");
	char log[128] = { 0 };
	sprintf(log, "PARA objNo:%d,UID:%d,opFare:%d,jyDT:%s", objNo, uid, opFare, jyDT);
	//W_ReadCardLog(log);

	/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
	if (HIns_CAP == NULL)
	{
		//W_ReadCardLog("ERROR -1801 Ѱ�����ض�̬��ʧ��");
		return -1801;
	}
	else
	{
		setcardinfo_str set_cardstr = (setcardinfo_str)GetProcAddress(HIns_CAP, "CapSetNBCardInfo_Str");
		if (set_cardstr == NULL)
		{
			////W_ReadCardLog("ERROR -1701 δ���ҵ�CapSetNBCardInfo_Str�ӿ�");
			//FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			long status_setcardstr = set_cardstr(objNo, uid, opFare, jyDT, psamID, psamJyNo, tac, redix);
			char* str_jydt = jyDT;

			//char* str_tac = tac;
			char _log[512];
			sprintf(_log, "PARA objNO:%ld,UID:%ld,opFare:%ld,jyDT:%s,redix:%d,psamID:%lld,psamJyNo:%ld,tac:%s;status:%d", objNo, uid, opFare, str_jydt, redix, psamID, psamJyNo, tac, status_setcardstr);
			//W_log(_log);	//ԭ��־���ã����ϵ�./Log/ReadCard.log
			//W_ReadCardLog(_log);
			//FreeLibrary(hdllInst);
			return status_setcardstr;
		}
	}

}
//�ۿ�����ϴ�����
long _stdcall CapSetNBCardInfo_Str(long objNo, long uid, long opFare, LPSTR jyDT, __int64 *psamID, long *psamJyNo, char *tac, int redix)
{
	W_ReadCardLog("EVENT CapSetNBCardInfo_Str START");
	// JudgeHDDType();
	char outmsg[2048] = { 0 };
	int ret = GetComInputInfo(outmsg);
	if (ret == 0)
	{
		Json::Value sendvalue;
		string orgcode(GetValueInIni("MIS", "ORGCODE", iniFileName));
		string serialNo(GetValueInIni("MIS", "SERIALNO", iniFileName));
		sendvalue["organizationCode"] = orgcode;
		sendvalue["serialNumber"] = serialNo;
		sendvalue["method"] = "pay";
		//ʹ��17λʱ�����Ϊ������
		std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::system_clock::now().time_since_epoch());
		sendvalue["content"]["orderNo"] = ms.count();
		sendvalue["content"]["orderTime"] = TransDate(jyDT);
		sendvalue["content"]["txnAmt"] = opFare;
		sendvalue["content"]["termId"] = atoll(GetValueInIni("MIS", "TERMID", iniFileName));//�ն˺�
		sendvalue["content"]["reqType"] = "��������";
		sendvalue["content"]["couponInfo"] = 0;
		sendvalue["content"]["qrNo"] = outmsg;
		sendvalue["content"]["merId"] = GetValueInIni("MIS", "MERID", iniFileName);
		sendvalue["content"]["merCatCode"] = GetValueInIni("MIS", "MERCATCODE", iniFileName);
		sendvalue["content"]["merName"] = GetValueInIni("MIS", "MERNAME", iniFileName);
		string sendJson = sendvalue.toStyledString();
		char _send_buff[1024] = { 0 };
		memcpy(_send_buff, sendJson.c_str(), 1024);
		W_ReadCardLog(_send_buff);
		//�ύ�ӿ�
		LPSTR req_ip;
		req_ip = GetValueInIni("MIS", "BCNIP", iniFileName);
		short _port = GetPrivateProfileIntA("MIS", "BCNPORT", 80, iniFileName);
		char req_resv[1024] = { 0 };
		long ret_sendpost = SendPostRequest(req_ip, _port, _send_buff, req_resv);
		if (0 == ret_sendpost)
		{
			char _rev_temp[1024] = { 0 };
			TransCharacter(req_resv, _rev_temp);
			//��ȡjson
			string str_rev(_rev_temp);
			string json_rel;
			int json_bg = str_rev.find_first_of("{", 0);
			int json_end = str_rev.find_last_of("}");
			if (json_end > json_bg)
			{
				json_rel = str_rev.substr(json_bg, json_end - json_bg + 1);
				W_ReadCardLog(json_rel.c_str());
				//����Jsonʾ����
				//{"code":"R00000","content":{"data":{"orderNo":"1558334758179","payResult":"�ɹ�","autoCode":"0","termId":"1"}},"desc":"֧���ɹ�","flag":1}
				//����json
				Json::Value root;
				//js_vl.clear();
				Json::Reader reader;
				try
				{
					if (reader.parse(json_rel, root))
					{
						if (root["flag"].asString() == "1")
						{
							W_ReadCardLog("INFO ֧���ɹ�");
							//�������
							*psamID = atoll(GetValueInIni("MIS", "TERMID", iniFileName));
							char tac_temp[20] = { 0 };
							_i64toa(ms.count(), tac_temp, 10);
							strcpy(tac, tac_temp);
							*psamJyNo = atol(root["content"]["data"]["autoCode"].asString().c_str());
							return 0;
						}
						else
						{
							W_ReadCardLog("ERROR ֧��ʧ��");
							return -11;
						}
					}
				}
				catch (const std::exception&ex)
				{
					return -13;
				}

			}
			else
			{
				W_ReadCardLog("ERROR ������Ϣ��ʽ����");
				return -12;
			}
		}
		else
		{
			return ret_sendpost;
		}
	}
	else
	{
		return -1;
	}


}
//5.13.	��ȡtacֵ
long _stdcall CapGetConsumeTac(long no, LPSTR tac)
{
	/*std::thread t(OpFile);
	t.detach();*/
	return -1;
}
//��ȡʮ�ν��׼�¼
long _stdcall CapReadRecords(CONSUMEINFO* info)
{
	return -1;
}

//�۷ѣ������ϴ�����
long _stdcall CapSetNBCardInfo(long objNo, long UID, long opFare, LPSTR jyDT, __int64 *psamID, long *psamJyNo, __int64 *tac)
{
	//W_ReadCardLog("EVENT ���ú���CapSetNBCardInfo��ʼ");
	Json::Value Charging;
	Json::FastWriter fw;
	if (VerifiBlackCard_UID(UID) != 0)
	{
		return -777;
	}
	else
	{
		/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
		if (HIns_CAP == NULL)
		{
			//W_ReadCardLog("ERROR -1801 Ѱ�����ض�̬��ʧ��");

			return -1801;
		}
		else
		{
			setcardinfo Set_CardInfo = (setcardinfo)GetProcAddress(HIns_CAP, "CapSetNBCardInfo");
			if (Set_CardInfo == NULL)
			{
				//W_ReadCardLog("ERROR -1701 δ���ҵ�CapSetNBCardInfo�ӿ�");
				//FreeLibrary(hdllInst);
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
				__int64* _tac = tac;
				long status_setinfo = Set_CardInfo(_objNo, _UID, _opFare, _jyDT, _psamID, _psamJyNo, _tac);
				__int64 pid = *_psamID;
				long pjyno = *_psamJyNo;
				__int64 tc = *_tac;
				//��¼�ۿ���־

				//char _log[256] = { 0 };
				//sprintf(_log, "PARA objNO:%ld,UID:%ld,opFare:%ld,jyDT:%s,psamID:%lld,psamJyNo:%ld,tac:%lld;status:%ld", _objNo, _UID, _opFare, _jyDT, pid, pjyno, tc, status_setinfo);
				//W_log(_log);
				//W_ReadCardLog(_log);
				//FreeLibrary(hdllInst);
				return status_setinfo;
			}
		}
	}

}

#pragma endregion

#pragma region ���񽡿����ӿ�

HANDLE _stdcall OpenDevice(int port)
{
	W_ReadCardLog("EVENT OpenDevice START");
	string testpath = ".\\ChgCity.ini";
	FILE *fp = fopen(testpath.data(), "r");

	if (!fp)
	{
		strcpy(iniFileName, "D:\\ChgCity.ini");
	}
	else
	{
		strcpy(iniFileName, testpath.c_str());
	}
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	// JudgeHDDType();
	if (HDDTYPE == 3)
	{
		/*HMODULE hinstance = LoadLibraryA(CAPDLL);*/
		if (HIns_CAP == NULL)
		{
			return (HANDLE)0;
		}
		else
		{
			opendevice OPDV = (opendevice)GetProcAddress(HIns_CAP, "OpenDevice");
			if (OPDV == NULL)
			{
				//FreeLibrary(hinstance);
				return (HANDLE)0;
			}
			else
			{

				W_ReadCardLog("OPEN DEVICE");
				HANDLE h_status = OPDV(port);
				//FreeLibrary(hinstance);
				return h_status;
			}

		}
	}
	else
	{
		return (HANDLE)0;
	}
}
int _stdcall CloseDevice(HANDLE hdev)
{
	W_ReadCardLog("EVENT CloseDevice START");

	HDDTYPE = -1;
	return 0;
}
int _stdcall PowerOn(HANDLE hdev, int slot, char* atr)
{
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (HDDTYPE == 3)
	{
		/*HMODULE hdllInst = LoadLibraryA(CAPDLL);*/
		if (HIns_CAP == NULL)
		{
			return -1801;
		}
		else
		{
			poweron power_on = (poweron)GetProcAddress(HIns_CAP, "PowerOn");
			if (power_on == NULL)
			{
				//FreeLibrary(hdllInst);
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
	else
	{
		return 0;
	}
}
int _stdcall SendAPDU(HANDLE hdev, unsigned char byslot, unsigned char* pbyccommand, unsigned long len, unsigned char* pbyrcommand, int* pnrs)
{
	return 0;
}
int _stdcall iR_DDF1EF05Info(HANDLE hdev, char* klb, char* gfbb, char* fkjgmc, char* fkjgdm, char* fkjgzs, char* fksj, char* kh, char* aqm, char* xpxlh, char* yycsdm)
{
	W_ReadCardLog("EVENT iR_DDF1EF05Info START");
	int ret = -1;
	char outMsg[1024] = { 0 };
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (HDDTYPE == 3)
	{
		/*HMODULE hdllInst = LoadLibraryA(CAPDLL);*/
		r_ddf1ef05 ef05 = (r_ddf1ef05)GetProcAddress(HIns_CAP, "iR_DDF1EF05Info");
		if (ef05 == NULL)
		{
			//FreeLibrary(hdllInst);
			return -1701;
		}
		else
		{
			ret = ef05(hdev, klb, gfbb, fkjgmc, fkjgdm, fkjgzs, fksj, kh, aqm, xpxlh, yycsdm);
			///FreeLibrary(hdllInst);
		}
	}
	if (ret != 0)//�û�����λʧ�ܣ�����ɨ��
	{
		if (js_vl["flag"].asString() == "1")
		{
			W_ReadCardLog("INFO ��ѯ�ɹ�");
			/*Json::Value js_dep;
			Json::Reader reader;
			string str_dep = decrypt(js_vl["data"].asString());
			reader.parse(str_dep, js_dep);*/
			//�������
			strcpy(kh, js_vl["content"]["data"]["papersNum"].asString().c_str());
			strcpy(ALLIDCARD, kh);
			return 0;
		}
		else
		{
			W_ReadCardLog("ERROR ��ѯʧ��");
			return -11;
		}
	}
	else
	{
		return -1;
	}
}
int _stdcall iW_DDF1EF05Info(HANDLE hdev, char* klb, char* gfbb, char* fkjgmc, char* fkjgdm, char* fkjgzs, char* fksj, char* kh, char* aqm, char* xpxlh, char* yycsdm)
{
	return 0;
}
int _stdcall iR_DDF1EF06Info(HANDLE hdev, char* xm, char* xb, char* mz, char* csrq, char* sfzh)
{
	W_ReadCardLog("EVENT iR_DDF1EF06Info START");

	int ret = -1;
	RTYPE = -1;
	char outMsg[1024] = { 0 };
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (HDDTYPE == 3)
	{
		//HMODULE hdllInst = LoadLibraryA(CAPDLL);
		r_ddf1ef06 ef06 = (r_ddf1ef06)GetProcAddress(HIns_CAP, "iR_DDF1EF06Info");
		if (ef06 == NULL)
		{
			FreeLibrary(HIns_CAP);
			return -1701;
		}
		else
		{
			char _xm[20] = { 0 };
			char _xb[20] = { 0 };
			char _mz[20] = { 0 };
			char _csrq[30] = { 0 };
			char _sfzh[20] = { 0 };
			ret = ef06(hdev, _xm, _xb, _mz, _csrq, _sfzh);
			strcpy(xm, _xm);
			strcpy(xb, _xb);
			strcpy(mz, _mz);
			strcpy(csrq, _csrq);
			strcpy(sfzh, _sfzh);
			char log[100];
			sprintf(log, "READ EF06 STATUS:%d,CNAME:%s,GENDER:%s,SFZ:%s", ret, _xm, _xb, _sfzh);
			W_ReadCardLog(log);
			//FreeLibrary(hdllInst);

		}
	}
	if (HDDTYPE == 2)//���������
	{
		//HMODULE hdllInst = LoadLibraryA(CONDLL);
		if (HIns_WQ == NULL)
		{
			return -1801;
		}
		else
		{
			//����W2160��������Ϣ��ҪPSAM��
			//2019��12��3��14:18:59 ͨ����ȡ���֤�ź��ѯ��Ϣ
			readcardinfo ef05 = (readcardinfo)GetProcAddress(HIns_WQ, "ReadCardInfo");
			if (ef05 == NULL)
			{
				//FreeLibrary(hdllInst);
				W_ReadCardLog("ERROR iR_DDF1EF06Info ��������ӿ�ReadCardInfoʧ��");
				return -1701;
			}
			else
			{
				char errMsg[1024] = { 0 };
				ret = ef05(outMsg, errMsg);
				/*char log[1024];
				sprintf(log, "DF1EF06 ����״̬��%d,������Ϣ��%s��������Ϣ��%s", ret, outMsg, errMsg);
				W_ReadCardLog(log);*/
				if (ret == 0) //�����ɹ�
				{
					RTYPE = 1;
					v.clear();
					string strOutMsg(outMsg);
					my_split(strOutMsg, c_spliter, v);
					strcpy(sfzh, v[5].c_str());
					memset(outMsg, 0x00, sizeof(outMsg));
					if (strlen(sfzh) > 14)
					{


						//�������֤�Ų�ѯ������Ϣ
						char outJson[2048] = { 0 };
						long cardtype = 1;	//ʵ�忨
						long ret = GetCusInfoByUnion(cardtype, sfzh, outJson);
						if (ret == 0)
						{
							//����json
							js_vl.clear();
							Json::Reader reader;
							try
							{
								string strJson(outJson);
								reader.parse(strJson, js_vl);
								if (js_vl["flag"].asString() == "1")//��ѯ�ɹ�
								{
									W_ReadCardLog("INFO ��ѯ�ɹ�");
									//�������
									strcpy(xm, js_vl["content"]["data"]["userName"].asString().c_str());
									strcpy(sfzh, js_vl["content"]["data"]["papersNum"].asString().c_str());
									if (18 == strlen(sfzh))
									{
										string str_sfz(sfzh);
										string str_sex = str_sfz.substr(16, 1);
										string str_csrq = str_sfz.substr(6, 8);
										int sex = (stoi(str_sex) % 2) == 0 ? 2 : 1;
										itoa(sex, xb, 10);
										strcpy(csrq, str_csrq.c_str());
									}
									return 0;
								}
								else
								{
									W_ReadCardLog("ERROR ��ѯʧ��");
									return -11;
								}

							}
							catch (const std::exception&ex)
							{
								W_ReadCardLog("���ܳ����쳣�˳�");
								return -13;
							}
						}
					}
					else
					{
						W_ReadCardLog("ERROR iR_DDF1EF06Info ���Ÿ�ʽ����ȷ");
						return -14;
					}
				}
			}
		}
	}
	if (ret != 0)
	{
		RTYPE = 2;
		int rc = GetComInputInfo(outMsg);
		if (rc == 0)//ɨ��ɹ�
		{
			char req_resv[1024];
			LPSTR req_ip;
			req_ip = GetValueInIni("MIS", "BCNIP", iniFileName);
			short _port = GetPrivateProfileIntA("MIS", "BCNPORT", 80, iniFileName);
			char log[100];
			sprintf(log, "�����ļ�IP��%s,PORT:%d", req_ip, _port);
			W_ReadCardLog(log);

			//���岢��ʼ��Json����
			Json::Value sendvalue;
			//string content(_info);
			string orgcode(GetValueInIni("MIS", "ORGCODE", iniFileName));
			string serialNo(GetValueInIni("MIS", "SERIALNO", iniFileName));
			/*
			==========================

			req_ip = "10.241.0.138";
			_port = 8090;
			orgcode = "Y000001";
			serialNo = "JCYH000001";

				=====================
			*/
			sendvalue["content"] = outMsg;
			sendvalue["organizationCode"] = orgcode;
			sendvalue["serialNumber"] = serialNo;
			sendvalue["method"] = "search";
			string sendJson = sendvalue.toStyledString();
			char _send_buff[1024] = { 0 };
			string str_sendbuff = sendJson;
			memcpy(_send_buff, str_sendbuff.c_str(), 1024);
			//initKV();
			//string str_sendbuff = encrypt(sendJson);
			//memcpy(_send_buff, str_sendbuff.c_str(), 1024);

			W_ReadCardLog(str_sendbuff.c_str());
			//�ύ�ӿ�
			long ret_sendpost = SendPostRequest(req_ip, _port, _send_buff, req_resv);
			if (0 == ret_sendpost)
			{
				char _rev_temp[1024] = { 0 };
				TransCharacter(req_resv, _rev_temp);//��������
													//��ȡjson
				string str_rev(_rev_temp);
				string json_rel;
				int json_bg = str_rev.find_first_of("{", 0);
				int json_end = str_rev.find_last_of("}");
				if (json_end > json_bg)
				{
					json_rel = str_rev.substr(json_bg, json_end - json_bg + 1);
					W_ReadCardLog(json_rel.c_str());
					//����json
					js_vl.clear();
					Json::Reader reader;
					Json::Value js_dep;
					try
					{
						if (reader.parse(json_rel, js_vl))
						{
							if (js_vl["flag"].asString() == "1")
							{
								try
								{
									//string str_dep = decrypt(js_vl["content"]["data"].asString());
									//char deptemp[1024] = { 0 };
									//TransCharacter(str_dep.c_str(), deptemp);
									//string strtemp(deptemp);
									//string strlog = "���ܺ��ַ�����" + strtemp;
									//W_ReadCardLog(strlog.c_str());
									//reader.parse(strtemp, js_dep);
									W_ReadCardLog("JSON�������");
									strcpy(xm, js_vl["content"]["data"]["userName"].asString().c_str());
									strcpy(sfzh, js_vl["content"]["data"]["papersNum"].asString().c_str());
									/*strcpy(xm, js_dep["userName"].asString().c_str());
									strcpy(sfzh, js_dep["papersNum"].asString().c_str());*/
									strcpy(ALLIDCARD, sfzh);
									if (18 == strlen(sfzh))
									{
										string str_sfz(sfzh);
										string str_sex = str_sfz.substr(16, 1);
										string str_csrq = str_sfz.substr(6, 8);
										int sex = (stoi(str_sex) % 2) == 0 ? 2 : 1;
										itoa(sex, xb, 10);
										strcpy(csrq, str_csrq.c_str());
										char log[200] = { 0 };
										sprintf(log, "������%s,�Ա�%s,�������ڣ�%s,���֤�ţ�%s", xm, xb, csrq, sfzh);
										W_ReadCardLog(log);
										return 0;
									}
								}
								catch (const std::exception&)
								{
									return -1;
								}
							}
							else
							{
								W_ReadCardLog("ERROR ��ѯʧ��");
								return -11;
							}
						}
					}
					catch (const std::exception&ex)
					{
						return -13;
					}

				}
				else
				{
					W_ReadCardLog("ERROR ������Ϣ��ʽ����");
					return -12;
				}
			}
			else
			{
				return ret_sendpost;
			}
		}
		else
		{
			return rc;
		}


	}
}
int _stdcall iW_DDF1EF06Info(HANDLE hdev, char* xm, char* xb, char* mz, char* csrq, char* sfzh)
{
	return 0;
}
int _stdcall iR_DDF1EF07Info(HANDLE hdev, char* zp_path)
{
	W_ReadCardLog("EVENT iR_DDF1EF07Info START");

	return 0;
}
int _stdcall iW_DDF1EF07Info(HANDLE hdev, char* zp_path)
{
	return 0;
}
int _stdcall iR_DDF1EF08Info(HANDLE hdev, char* kyxq, char* brdh1, char* brdh2, char* ylfs1, char* ylfs2, char* ylfs3)
{
	W_ReadCardLog("EVENT iR_DDF1EF08Info START");
	int ret = -1;
	char outMsg[1024] = { 0 };
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (HDDTYPE == 3)
	{
		/*HMODULE hdllInst = LoadLibraryA(CAPDLL);*/
		if (HIns_CAP == NULL)
		{
			return -1801;
		}
		else
		{
			r_ddf1ef08 ef08 = (r_ddf1ef08)GetProcAddress(HIns_CAP, "iR_DDF1EF08Info");
			if (ef08 == NULL)
			{
				W_ReadCardLog("DDF1EF08");
				//FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{

				ret = ef08(hdev, kyxq, brdh1, brdh2, ylfs1, ylfs2, ylfs3);
				//FreeLibrary(hdllInst);
			}
		}
	}
	if (ret != 0)
	{
		if (js_vl["flag"].asString() == "1")
		{
			/*Json::Value js_dep;
			Json::Reader reader;
			string str_dep = decrypt(js_vl["data"].asString());
			reader.parse(str_dep, js_dep);*/
			//�������
			try
			{
				strcpy(brdh1, js_vl["content"]["data"]["telephone"].asString().c_str());
				strcpy(brdh2, js_vl["content"]["data"]["telephone"].asString().c_str());
				return 0;
			}
			catch (const std::exception&)
			{
				return -1;
			}

		}
		else
		{
			return -11;
		}
	}
	else
	{
		return -1;
	}
}
int _stdcall iW_DDF1EF08Info(HANDLE hdev, char* kyxq, char* brdh1, char* brdh2, char* ylfs1, char* ylfs2, char* ylfs3)
{
	return 0;
}
int _stdcall iR_DF01EF05Info(HANDLE hdev, char* dzlb1, char* dz1, char* dzlb2, char* dz2)
{
	W_ReadCardLog("EVENT iR_DF01EF05Info START");

	int ret = -1;
	char outMsg[1024] = { 0 };
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (RTYPE == 1)
	{
		if (HDDTYPE == 3)
		{
			//HMODULE hdllInst = LoadLibraryA(CAPDLL);
			if (HIns_CAP == NULL)
			{
				return -1801;
			}
			else
			{
				r_df01ef05 df01ef05 = (r_df01ef05)GetProcAddress(HIns_CAP, "iR_DF01EF05Info");
				if (df01ef05 == NULL)
				{
					W_ReadCardLog("DF01EF05");

					//FreeLibrary(hdllInst);
					return -1701;
				}
				else
				{

					ret = df01ef05(hdev, dzlb1, dz1, dzlb2, dz2);
					//FreeLibrary(hdllInst);
				}
			}
		}
		if (HDDTYPE == 2)
		{
			/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
			if (HIns_WQ == NULL)
			{
				return -1801;
			}
			else
			{
				readpersoninfo df01ef05 = (readpersoninfo)GetProcAddress(HIns_WQ, "ReadPeopleInfo");
				if (df01ef05 == NULL)
				{
					W_ReadCardLog("DF01EF05");

					//FreeLibrary(hdllInst);
					return -1701;
				}
				else
				{
					char errMsg[1024] = { 0 };
					ret = df01ef05(outMsg, errMsg);
					if (ret == 0)//�����񽡿����ɹ�
					{
						v.clear();
						string strOutMsg(outMsg);
						my_split(strOutMsg, c_spliter, v);
						strcpy(dzlb1, v[11].c_str());
						strcpy(dz1, v[12].c_str());
						strcpy(dzlb2, v[13].c_str());
						strcpy(dz2, v[14].c_str());
						//FreeLibrary(hdllInst);
						return 0;
					}


				}
			}
		}
	}
	if (RTYPE = 2)
	{
		W_ReadCardLog("RTYPE 2");
		if (js_vl["flag"].asString() == "1")
		{
			/*Json::Value js_dep;
			Json::Reader reader;
			string str_dep = decrypt(js_vl["data"].asString());
			reader.parse(str_dep, js_dep);*/
			//�������
			try
			{
				string straddr = js_vl["content"]["data"]["patientAddr"].asString();
				strcpy(dz1, js_vl["content"]["data"]["patientAddr"].asString().c_str());
				strcpy(dz2, js_vl["content"]["data"]["permanentResiAddr"].asString().c_str());
				return 0;
			}
			catch (const std::exception&)
			{
				return -1;
			}

		}
		else
		{
			return -11;
		}
	}
	else
	{
		return -1;
	}
}
int _stdcall iW_DF01EF05Info(HANDLE hdev, char* dzlb1, char* dz1, char* dzlb2, char* dz2)
{
	return 0;
}
int _stdcall iR_DF01EF06Info(HANDLE hdev, char* xm1, char* gx1, char* dh1, char* xm2, char* gx2, char* dh2, char* xm3, char* gx3, char* dh3)
{
	W_ReadCardLog("EVENT iR_DF01EF06Info START");
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (RTYPE == 1)
	{
		int ret = -1;
		char outMsg[1024] = { 0 };
		if (HDDTYPE == 3)
		{
			/*HMODULE hdllInst = LoadLibraryA(CAPDLL);*/
			if (HIns_CAP == NULL)
			{
				return -1801;
			}
			else
			{
				r_df01ef06 df01ef06 = (r_df01ef06)GetProcAddress(HIns_CAP, "iR_DF01EF06Info");
				if (df01ef06 == NULL)
				{
					W_ReadCardLog("DF01EF06");

					//FreeLibrary(hdllInst);
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
					ret = df01ef06(_hdev, _xm1, _gx1, _dh1, _xm2, _gx2, _dh2, _xm3, _gx3, _dh3);
					//FreeLibrary(hdllInst);
					return ret;
				}
			}
		}
		if (HDDTYPE == 2)
		{


			/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
			if (HIns_WQ == NULL)
			{
				return -1801;
			}
			else
			{
				readpersoninfo df01ef06 = (readpersoninfo)GetProcAddress(HIns_WQ, "ReadPeopleInfo");
				if (df01ef06 == NULL)
				{
					W_ReadCardLog("DF01EF06");

					//FreeLibrary(hdllInst);
					return -1701;
				}
				else
				{

					char errMsg[1024] = { 0 };
					ret = df01ef06(outMsg, errMsg);

					if (ret == 0)
					{
						v.clear();
						string strOutMsg(outMsg);
						my_split(strOutMsg, c_spliter, v);
						strcpy(xm1, v[15].c_str());
						strcpy(gx1, v[16].c_str());
						strcpy(dh1, v[17].c_str());
						strcpy(xm2, v[18].c_str());
						strcpy(gx2, v[20].c_str());
						strcpy(dh2, v[21].c_str());
						strcpy(xm3, v[22].c_str());
						strcpy(gx3, v[23].c_str());
						strcpy(dh3, v[24].c_str());
						//FreeLibrary(hdllInst);
					}
					return ret;
				}
			}
		}
	}
}
int _stdcall iW_DF01EF06Info(HANDLE hdev, char* xm1, char* gx1, char* dh1, char* xm2, char* gx2, char* dh2, char* xm3, char* gx3, char* dh3)
{
	return -2;
}
int _stdcall iR_DF01EF07Info(HANDLE hdev, char* whcd, char* hyzk, char* zy)
{
	W_ReadCardLog("EVENT iR_DF01EF07Info START");
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (RTYPE == 1)
	{
		if (HDDTYPE == 3)
		{
			/*HMODULE hdllInst = LoadLibraryA(CAPDLL);*/
			if (HIns_CAP == NULL)
			{
				return -1801;
			}
			else
			{
				r_df01ef07 df01ef07 = (r_df01ef07)GetProcAddress(HIns_CAP, "iR_DF01EF07Info");
				if (df01ef07 == NULL)
				{
					W_ReadCardLog("DF01EF07");

					//FreeLibrary(hdllInst);
					return -1701;
				}
				else
				{
					int stauts_df01ef07 = df01ef07(hdev, whcd, hyzk, zy);
					//FreeLibrary(hdllInst);
					return stauts_df01ef07;
				}
			}
		}
		if (HDDTYPE == 2)
		{


			/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
			if (HIns_WQ == NULL)
			{
				return -1801;
			}
			else
			{
				readpersoninfo df01ef07 = (readpersoninfo)GetProcAddress(HIns_WQ, "ReadPeopleInfo");
				if (df01ef07 == NULL)
				{
					W_ReadCardLog("DF01EF07");

					//FreeLibrary(hdllInst);
					return -1701;
				}
				else
				{
					char outMsg[65535] = { 0 };
					char errMsg[1024] = { 0 };
					int stauts_df01ef07 = df01ef07(outMsg, errMsg);
					char log[100];
					sprintf(log, "����״̬��%d", stauts_df01ef07);
					W_ReadCardLog(log);
					if (stauts_df01ef07 == 0)
					{
						v.clear();
						string strOutMsg(outMsg);
						my_split(strOutMsg, c_spliter, v);
						strcpy(whcd, v[25].c_str());
						strcpy(hyzk, v[26].c_str());
						strcpy(zy, v[27].c_str());
						//FreeLibrary(hdllInst);
					}
					return stauts_df01ef07;

				}
			}
		}
	}
	else
	{
		return 0;
	}
}
int _stdcall iW_DF01EF07Info(HANDLE hdev, char* whcd, char* hyzk, char* zy)
{
	return 0;
}
int _stdcall iR_DF01EF08Info(HANDLE hdev, char* zjlb, char* zjhm, char* jkdah, char* xnhzh)
{
	W_ReadCardLog("EVENT iR_DF01EF08Info START");
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (RTYPE == 1)
	{


		if (HDDTYPE == 3)
		{
			/*HMODULE hdllInst = LoadLibraryA(CAPDLL);*/
			if (HIns_CAP == NULL)
			{
				return -1801;
			}
			else
			{
				r_df01ef08 df01ef08 = (r_df01ef08)GetProcAddress(HIns_CAP, "iR_DF01EF08Info");
				if (df01ef08 == NULL)
				{
					W_ReadCardLog("DF01EF08");

					//FreeLibrary(hdllInst);
					return -1701;
				}
				else
				{
					int stauts_df01ef08 = df01ef08(hdev, zjlb, zjhm, jkdah, xnhzh);
					//FreeLibrary(hdllInst);
					return stauts_df01ef08;
				}
			}
		}
		if (HDDTYPE == 2)
		{


			/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
			if (HIns_WQ == NULL)
			{
				return -1801;
			}
			else
			{
				readpersoninfo df01ef08 = (readpersoninfo)GetProcAddress(HIns_WQ, "ReadPeopleInfo");
				if (df01ef08 == NULL)
				{
					W_ReadCardLog("DF01EF08");

					//FreeLibrary(hdllInst);
					return -1701;
				}
				else
				{
					char outMsg[65535] = { 0 };
					char errMsg[1024] = { 0 };
					int stauts_df01ef08 = df01ef08(outMsg, errMsg);
					char log[100];
					sprintf(log, "����״̬��%d", stauts_df01ef08);
					W_ReadCardLog(log);
					if (stauts_df01ef08 == 0)
					{
						v.clear();
						string strOutMsg(outMsg);
						my_split(strOutMsg, c_spliter, v);
						strcpy(zjlb, v[27].c_str());
						strcpy(zjhm, v[28].c_str());
						strcpy(jkdah, v[29].c_str());
						strcpy(xnhzh, v[30].c_str());
						//FreeLibrary(hdllInst);
					}

					return stauts_df01ef08;
				}
			}
		}
	}
}
int _stdcall iW_DF01EF08Info(HANDLE hdev, char* zjlb, char* zjhm, char* jkdah, char* xnhzh)
{
	return 0;
}
int _stdcall iR_DF02EF05Info(HANDLE hdev, char* abo, char* rh, char* xc, char* xzb, char* xnxgb, char* dxb, char* nxwl, char* tnb, char* qgy, char* tx, char* qgyz, char* qgqs, char* kzxyz, char* xzqbq, char* qtyxjs)
{
	W_ReadCardLog("EVENT iR_DF02EF05Info START");
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (RTYPE == 1)
	{
		if (HDDTYPE == 3)
		{
			/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
			if (HIns_CAP == NULL)
			{
				return -1801;
			}
			else
			{
				r_df02ef05 df02ef05 = (r_df02ef05)GetProcAddress(HIns_CAP, "iR_DF02EF05Info");
				if (df02ef05 == NULL)
				{
					W_ReadCardLog("DF02EF05");

					//FreeLibrary(hdllInst);
					return -1701;
				}
				else
				{
					int stauts_df02ef05 = df02ef05(hdev, abo, rh, xc, xzb, xnxgb, dxb, nxwl, tnb, qgy, tx, qgyz, qgqs, kzxyz, xzqbq, qtyxjs);
					//FreeLibrary(hdllInst);
					return stauts_df02ef05;
				}
			}
		}
		else
		{
			return 0;
		}
	}
}
int _stdcall iW_DF02EF05Info(HANDLE hdev, char* abo, char* rh, char* xc, char* xzb, char* xnxgb, char* dxb, char* nxwl, char* tnb, char* qgy, char* tx, char* qgyz, char* qgqs, char* kzxyz, char* xzqbq, char* qtyxjs)
{
	return 0;
}
int _stdcall iR_DF02EF06Info(HANDLE hdev, char* jsb)
{
	return 0;
}
int _stdcall iW_DF02EF06Info(HANDLE hdev, char* jsb)
{
	return 0;
}
int _stdcall iR_DF02EF07Info(HANDLE hdev, int recordNo, char* gmwz, char* gmmc)
{
	return 0;
}
int _stdcall iW_DF02EF07Info(HANDLE hdev, char* gmwz, char* gmmc)
{
	return 0;
}
int _stdcall iR_DF02EF08Info(HANDLE hdev, int recordNo, char* jzmc, char* jzsj)
{
	return 0;
}
int _stdcall iW_DF02EF08Info(HANDLE hdev, char* jzmc, char* jzsj)
{
	return 0;
}
int _stdcall iR_DF03EF05Info(HANDLE hdev, char* jl1, char* jl2, char* jl3)
{
	return 0;
}
int _stdcall iW_DF03EF05Info(HANDLE hdev, int recordNo)
{
	return 0;
}
int _stdcall iErase_DF03EF05Info(HANDLE hdev, int recordNo)
{
	return 0;
}
int _stdcall iR_DF03EF06Info(HANDLE hdev, char* mzbs1, char* mzbs2, char* mzbs3, char* mzbs4, char* mzbs5)
{
	return 0;
}
int _stdcall iW_DF03EF06Info(HANDLE hdev, int record)
{
	return 0;
}
int _stdcall iErase_DF03EF06Info(HANDLE hdev, int record)
{
	return 0;
}
int _stdcall iR_DF03EEInfo(HANDLE hdev, int record, char* szdata, int npos, int nlen, int nstyle)
{
	W_ReadCardLog("EVENT iR_DF03EEInfo START");
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (HDDTYPE == 3)
	{
		/*HMODULE hdllInst = LoadLibraryA(CAPDLL);*/
		if (HIns_CAP == NULL)
		{
			return -1801;
		}
		else
		{
			r_df03ee df03ee = (r_df03ee)GetProcAddress(HIns_CAP, "iR_DF03EEInfo");
			if (df03ee == NULL)
			{
				W_ReadCardLog("DF03EE");

				//FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				int stauts_df03ee = df03ee(hdev, record, szdata, npos, nlen, nstyle);
				//FreeLibrary(hdllInst);
				return stauts_df03ee;
			}
		}
	}
	if (HDDTYPE == 2)
	{
		/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
		if (HIns_WQ == NULL)
		{
			return -1801;
		}
		else
		{
			readEEinfo df03ee = (readEEinfo)GetProcAddress(HIns_WQ, "ReadEEFileInfo");
			if (df03ee == NULL)
			{
				W_ReadCardLog("DF03EE");

				//FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				char outMsg[65535] = { 0 };
				char errMsg[1024] = { 0 };
				int stauts_df03ee = df03ee(record, outMsg, errMsg);
				if (stauts_df03ee == 0)
				{
					if ((npos == 0) && (nlen == 1639))//ȫ��
					{
						strcpy(szdata, outMsg);
					}
					else
					{
						v.clear();
						string strOutMsg(outMsg);
						my_split(strOutMsg, c_spliter, v);
						switch (npos)
						{
						case 0:strcpy(szdata, v[0].c_str());
							break;
						case 70: strcpy(szdata, v[1].c_str());
							break;
						case 80: strcpy(szdata, v[2].c_str());
							break;
						case 84: strcpy(szdata, v[3].c_str());
							break;
						case 86: strcpy(szdata, v[4].c_str());
							break;
						case 104: strcpy(szdata, v[5].c_str());
							break;
						case 154: strcpy(szdata, v[6].c_str());
							break;
						case 155: strcpy(szdata, v[7].c_str());
							break;
						case 205: strcpy(szdata, v[8].c_str());
							break;
						case 212: strcpy(szdata, v[9].c_str());
							break;
						case 213: strcpy(szdata, v[10].c_str());
							break;
						case 214: strcpy(szdata, v[11].c_str());
							break;
						case 264: strcpy(szdata, v[12].c_str());
							break;
						case 271: strcpy(szdata, v[13].c_str());
							break;
						case 275: strcpy(szdata, v[14].c_str());
							break;
						case 295: strcpy(szdata, v[15].c_str());
							break;
						case 296: strcpy(szdata, v[16].c_str());
							break;
						case 316: strcpy(szdata, v[17].c_str());
							break;
						case 317: strcpy(szdata, v[18].c_str());
							break;
						case 318: strcpy(szdata, v[19].c_str());
							break;
						case 398: strcpy(szdata, v[20].c_str());
							break;
						case 403: strcpy(szdata, v[21].c_str());
							break;
						case 407: strcpy(szdata, v[22].c_str());
							break;
						case 457: strcpy(szdata, v[23].c_str());
							break;
						case 458: strcpy(szdata, v[24].c_str());
							break;
						case 459: strcpy(szdata, v[25].c_str());
							break;
						case 460: strcpy(szdata, v[26].c_str());
							break;
						case 461: strcpy(szdata, v[27].c_str());
							break;
						case 511: strcpy(szdata, v[28].c_str());
							break;
						case 518: strcpy(szdata, v[29].c_str());
							break;
						case 522: strcpy(szdata, v[30].c_str());
							break;
						case 542: strcpy(szdata, v[31].c_str());
							break;
						case 543: strcpy(szdata, v[32].c_str());
							break;
						case 563: strcpy(szdata, v[33].c_str());
							break;
						case 564: strcpy(szdata, v[34].c_str());
							break;
						case 565: strcpy(szdata, v[35].c_str());
							break;
						case 645: strcpy(szdata, v[36].c_str());
							break;
						case 650: strcpy(szdata, v[37].c_str());
							break;
						case 654: strcpy(szdata, v[38].c_str());
							break;
						case 704: strcpy(szdata, v[39].c_str());
							break;
						case 705: strcpy(szdata, v[40].c_str());
							break;
						case 706: strcpy(szdata, v[41].c_str());
							break;
						case 707: strcpy(szdata, v[42].c_str());
							break;
						case 708: strcpy(szdata, v[43].c_str());
							break;
						case 758: strcpy(szdata, v[44].c_str());
							break;
						case 765: strcpy(szdata, v[45].c_str());
							break;
						case 769: strcpy(szdata, v[46].c_str());
							break;
						case 789: strcpy(szdata, v[47].c_str());
							break;
						case 790: strcpy(szdata, v[48].c_str());
							break;
						case 810: strcpy(szdata, v[49].c_str());
							break;
						case 811: strcpy(szdata, v[50].c_str());
							break;
						case 812: strcpy(szdata, v[51].c_str());
							break;
						case 892: strcpy(szdata, v[52].c_str());
							break;
						case 897: strcpy(szdata, v[53].c_str());
							break;
						case 901: strcpy(szdata, v[54].c_str());
							break;
						case 951: strcpy(szdata, v[55].c_str());
							break;
						case 952: strcpy(szdata, v[56].c_str());
							break;
						case 953: strcpy(szdata, v[57].c_str());
							break;
						case 954: strcpy(szdata, v[58].c_str());
							break;
						case 956: strcpy(szdata, v[59].c_str());
							break;
						case 966: strcpy(szdata, v[60].c_str());
							break;
						case 967: strcpy(szdata, v[61].c_str());
							break;
						case 969: strcpy(szdata, v[62].c_str());
							break;
						case 979: strcpy(szdata, v[63].c_str());
							break;
						case 980: strcpy(szdata, v[64].c_str());
							break;
						case 982: strcpy(szdata, v[65].c_str());
							break;
						case 992: strcpy(szdata, v[66].c_str());
							break;
						case 993: strcpy(szdata, v[67].c_str());
							break;
						case 995: strcpy(szdata, v[68].c_str());
							break;
						case 1005: strcpy(szdata, v[69].c_str());
							break;
						case 1007: strcpy(szdata, v[70].c_str());
							break;
						case 1009: strcpy(szdata, v[71].c_str());
							break;
						case 1013: strcpy(szdata, v[72].c_str());
							break;
						case 1063: strcpy(szdata, v[73].c_str());
							break;
						case 1066: strcpy(szdata, v[74].c_str());
							break;
						case 1067: strcpy(szdata, v[75].c_str());
							break;
						case 1068: strcpy(szdata, v[76].c_str());
							break;
						case 1069: strcpy(szdata, v[77].c_str());
							break;
						case 1089: strcpy(szdata, v[78].c_str());
							break;
						case 1090: strcpy(szdata, v[79].c_str());
							break;
						case 1095: strcpy(szdata, v[80].c_str());
							break;
						case 1115: strcpy(szdata, v[81].c_str());
							break;
						case 1116: strcpy(szdata, v[82].c_str());
							break;
						case 1121: strcpy(szdata, v[83].c_str());
							break;
						case 1141: strcpy(szdata, v[84].c_str());
							break;
						case 1142: strcpy(szdata, v[85].c_str());
							break;
						case 1147: strcpy(szdata, v[86].c_str());
							break;
						case 1167: strcpy(szdata, v[87].c_str());
							break;
						case 1168: strcpy(szdata, v[88].c_str());
							break;
						case 1173: strcpy(szdata, v[89].c_str());
							break;
						case 1193: strcpy(szdata, v[90].c_str());
							break;
						case 1194: strcpy(szdata, v[91].c_str());
							break;
						case 1199: strcpy(szdata, v[92].c_str());
							break;
						case 1219: strcpy(szdata, v[93].c_str());
							break;
						case 1220: strcpy(szdata, v[94].c_str());
							break;
						case 1225: strcpy(szdata, v[95].c_str());
							break;
						case 1245: strcpy(szdata, v[96].c_str());
							break;
						case 1246: strcpy(szdata, v[97].c_str());
							break;
						case 1251: strcpy(szdata, v[98].c_str());
							break;
						case 1271: strcpy(szdata, v[99].c_str());
							break;
						case 1272: strcpy(szdata, v[100].c_str());
							break;
						case 1277: strcpy(szdata, v[101].c_str());
							break;
						case 1297: strcpy(szdata, v[102].c_str());
							break;
						case 1298: strcpy(szdata, v[103].c_str());
							break;
						case 1303: strcpy(szdata, v[104].c_str());
							break;
						case 1323: strcpy(szdata, v[105].c_str());
							break;
						case 1324: strcpy(szdata, v[106].c_str());
							break;
						case 1329: strcpy(szdata, v[107].c_str());
							break;
						case 1349: strcpy(szdata, v[108].c_str());
							break;
						case 1350: strcpy(szdata, v[109].c_str());
							break;
						case 1355: strcpy(szdata, v[110].c_str());
							break;
						case 1375: strcpy(szdata, v[111].c_str());
							break;
						case 1376: strcpy(szdata, v[112].c_str());
							break;
						case 1381: strcpy(szdata, v[113].c_str());
							break;
						case 1401: strcpy(szdata, v[114].c_str());
							break;
						case 1402: strcpy(szdata, v[115].c_str());
							break;
						case 1407: strcpy(szdata, v[116].c_str());
							break;
						case 1427: strcpy(szdata, v[117].c_str());
							break;
						case 1428: strcpy(szdata, v[118].c_str());
							break;
						case 1433: strcpy(szdata, v[119].c_str());
							break;
						case 1453: strcpy(szdata, v[120].c_str());
							break;
						case 1454: strcpy(szdata, v[121].c_str());
							break;
						case 1459: strcpy(szdata, v[122].c_str());
							break;
						case 1479: strcpy(szdata, v[123].c_str());
							break;
						case 1480: strcpy(szdata, v[124].c_str());
							break;
						case 1485: strcpy(szdata, v[125].c_str());
							break;
						case 1505: strcpy(szdata, v[126].c_str());
							break;
						case 1506: strcpy(szdata, v[127].c_str());
							break;
						case 1511: strcpy(szdata, v[128].c_str());
							break;
						case 1531: strcpy(szdata, v[129].c_str());
							break;
						case 1532: strcpy(szdata, v[130].c_str());
							break;
						case 1537: strcpy(szdata, v[131].c_str());
							break;
						case 1557: strcpy(szdata, v[132].c_str());
							break;
						case 1558: strcpy(szdata, v[133].c_str());
							break;
						case 1563: strcpy(szdata, v[134].c_str());
							break;
						case 1583: strcpy(szdata, v[135].c_str());
							break;
						case 1584: strcpy(szdata, v[136].c_str());
							break;
						case 1589: strcpy(szdata, v[137].c_str());
							break;
						case 1594: strcpy(szdata, v[138].c_str());
							break;
						case 1599: strcpy(szdata, v[139].c_str());
							break;
						case 1604: strcpy(szdata, v[140].c_str());
							break;
						case 1609: strcpy(szdata, v[141].c_str());
							break;
						case 1614: strcpy(szdata, v[142].c_str());
							break;
						case 1619: strcpy(szdata, v[143].c_str());
							break;
						case 1624: strcpy(szdata, v[144].c_str());
							break;
						case 1629: strcpy(szdata, v[145].c_str());
							break;
						case 1634: strcpy(szdata, v[146].c_str());
							break;

						default:
							break;
						}
					}
				}
				//FreeLibrary(hdllInst);
				return stauts_df03ee;
			}
		}
	}

}
int _stdcall iW_DF03EEInfo(HANDLE hdev, int record, char* szdata, int npos, int nlen, int nstyle)
{
	W_ReadCardLog("EVENT iW_DF03EEInfo START");
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (HDDTYPE == 3)
	{
		/*HMODULE hdllInst = LoadLibraryA(CAPDLL);*/
		if (HIns_CAP == NULL)
		{
			return -1801;
		}
		else
		{
			w_df03ee df03ee = (w_df03ee)GetProcAddress(HIns_CAP, "iW_DF03EEInfo");
			if (df03ee == NULL)
			{
				//FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				int stauts_df03ee = df03ee(hdev, record, szdata, npos, nlen, nstyle);
				//FreeLibrary(hdllInst);
				return stauts_df03ee;
			}
		}
	}
	if (HDDTYPE == 2)
	{
		/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
		if (HIns_WQ == NULL)
		{
			return -1801;
		}
		else
		{
			//readEDinfo readED = (readEDinfo)GetProcAddress(hdllInst, "ReadEDFileInfo");
			writeEEinfo writeEE = (writeEEinfo)GetProcAddress(HIns_WQ, "WriteEEFileInfo");
			//if ((readED == NULL)||(writeED==NULL))
			if (writeEE == NULL)
			{
				//FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				char errMsg[1024] = { 0 };
				int ret = writeEE(szdata, errMsg);
				return ret;
			}
		}
	}
}
int _stdcall iR_DF03EDInfo(HANDLE hdev, int record, char* szdata, int npos, int nlen, int nstyle)
{
	W_ReadCardLog("EVENT iR_DF03EDInfo START");
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (HDDTYPE == 3)
	{
		/*HMODULE hdllInst = LoadLibraryA(CAPDLL);*/
		if (HIns_CAP == NULL)
		{
			return -1801;
		}
		else
		{
			r_df03ed df03ed = (r_df03ed)GetProcAddress(HIns_CAP, "iR_DF03EDInfo");
			if (df03ed == NULL)
			{
				W_ReadCardLog("DF03ED");

				//FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				int stauts_df03ed = df03ed(hdev, record, szdata, npos, nlen, nstyle);
				//FreeLibrary(hdllInst);
				return stauts_df03ed;
			}
		}
	}
	if (HDDTYPE == 2)
	{
		/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
		if (HIns_WQ == NULL)
		{
			return -1801;
		}
		else
		{
			readEDinfo df03ed = (readEDinfo)GetProcAddress(HIns_WQ, "ReadEDFileInfo");
			if (df03ed == NULL)
			{
				W_ReadCardLog("DF03ED");

				//FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				char outMsg[65535] = { 0 };
				char errMsg[1024] = { 0 };
				int stauts_df03ed = df03ed(record, outMsg, errMsg);
				if (stauts_df03ed == 0)
				{
					if ((npos == 0) && (nlen == 3013))//read all of info
					{
						strcpy(szdata, outMsg);
					}
					else
					{
						v.clear();
						string strOutMsg(outMsg);
						my_split(strOutMsg, c_spliter, v);
						switch (npos)
						{
						case 0:strcpy(szdata, v[0].c_str());
							break;
						case 70: strcpy(szdata, v[1].c_str());
							break;
						case 80: strcpy(szdata, v[2].c_str());
							break;
						case 87: strcpy(szdata, v[3].c_str());
							break;
						case 105: strcpy(szdata, v[4].c_str());
							break;
						case 155: strcpy(szdata, v[5].c_str());
							break;
						case 156: strcpy(szdata, v[6].c_str());
							break;
						case 206: strcpy(szdata, v[7].c_str());
							break;
						case 211: strcpy(szdata, v[8].c_str());
							break;
						case 215: strcpy(szdata, v[9].c_str());
							break;
						case 265: strcpy(szdata, v[10].c_str());
							break;
						case 272: strcpy(szdata, v[11].c_str());
							break;
						case 279: strcpy(szdata, v[12].c_str());
							break;
						case 281: strcpy(szdata, v[13].c_str());
							break;
						case 331: strcpy(szdata, v[14].c_str());
							break;
						case 336: strcpy(szdata, v[15].c_str());
							break;
						case 340: strcpy(szdata, v[16].c_str());
							break;
						case 390: strcpy(szdata, v[17].c_str());
							break;
						case 397: strcpy(szdata, v[18].c_str());
							break;
						case 404: strcpy(szdata, v[19].c_str());
							break;
						case 406: strcpy(szdata, v[20].c_str());
							break;
						case 456: strcpy(szdata, v[21].c_str());
							break;
						case 461: strcpy(szdata, v[22].c_str());
							break;
						case 465: strcpy(szdata, v[23].c_str());
							break;
						case 515: strcpy(szdata, v[24].c_str());
							break;
						case 522: strcpy(szdata, v[25].c_str());
							break;
						case 529: strcpy(szdata, v[26].c_str());
							break;
						case 531: strcpy(szdata, v[27].c_str());
							break;
						case 581: strcpy(szdata, v[28].c_str());
							break;
						case 586: strcpy(szdata, v[29].c_str());
							break;
						case 590: strcpy(szdata, v[30].c_str());
							break;
						case 640: strcpy(szdata, v[31].c_str());
							break;
						case 647: strcpy(szdata, v[32].c_str());
							break;
						case 654: strcpy(szdata, v[33].c_str());
							break;
						case 656: strcpy(szdata, v[34].c_str());
							break;
						case 706: strcpy(szdata, v[35].c_str());
							break;
						case 711: strcpy(szdata, v[36].c_str());
							break;
						case 715: strcpy(szdata, v[37].c_str());
							break;
						case 765: strcpy(szdata, v[38].c_str());
							break;
						case 772: strcpy(szdata, v[39].c_str());
							break;
						case 779: strcpy(szdata, v[40].c_str());
							break;
						case 781: strcpy(szdata, v[41].c_str());
							break;
						case 861: strcpy(szdata, v[42].c_str());
							break;
						case 862: strcpy(szdata, v[43].c_str());
							break;
						case 867: strcpy(szdata, v[44].c_str());
							break;
						case 887: strcpy(szdata, v[45].c_str());
							break;
						case 907: strcpy(szdata, v[46].c_str());
							break;
						case 987: strcpy(szdata, v[47].c_str());
							break;
						case 988: strcpy(szdata, v[48].c_str());
							break;
						case 993: strcpy(szdata, v[49].c_str());
							break;
						case 1013: strcpy(szdata, v[50].c_str());
							break;
						case 1033: strcpy(szdata, v[51].c_str());
							break;
						case 1113: strcpy(szdata, v[52].c_str());
							break;
						case 1114: strcpy(szdata, v[53].c_str());
							break;
						case 1119: strcpy(szdata, v[54].c_str());
							break;
						case 1139: strcpy(szdata, v[55].c_str());
							break;
						case 1159: strcpy(szdata, v[56].c_str());
							break;
						case 1239: strcpy(szdata, v[57].c_str());
							break;
						case 1240: strcpy(szdata, v[58].c_str());
							break;
						case 1245: strcpy(szdata, v[59].c_str());
							break;
						case 1265: strcpy(szdata, v[60].c_str());
							break;
						case 1285: strcpy(szdata, v[61].c_str());
							break;
						case 1365: strcpy(szdata, v[62].c_str());
							break;
						case 1366: strcpy(szdata, v[63].c_str());
							break;
						case 1371: strcpy(szdata, v[64].c_str());
							break;
						case 1391: strcpy(szdata, v[65].c_str());
							break;
						case 1411: strcpy(szdata, v[66].c_str());
							break;
						case 1491: strcpy(szdata, v[67].c_str());
							break;
						case 1492: strcpy(szdata, v[68].c_str());
							break;
						case 1497: strcpy(szdata, v[69].c_str());
							break;
						case 1517: strcpy(szdata, v[70].c_str());
							break;
						case 1537: strcpy(szdata, v[71].c_str());
							break;
						case 1617: strcpy(szdata, v[72].c_str());
							break;
						case 1618: strcpy(szdata, v[73].c_str());
							break;
						case 1623: strcpy(szdata, v[74].c_str());
							break;
						case 1643: strcpy(szdata, v[75].c_str());
							break;
						case 1663: strcpy(szdata, v[76].c_str());
							break;
						case 1743: strcpy(szdata, v[77].c_str());
							break;
						case 1744: strcpy(szdata, v[78].c_str());
							break;
						case 1749: strcpy(szdata, v[79].c_str());
							break;
						case 1769: strcpy(szdata, v[80].c_str());
							break;
						case 1789: strcpy(szdata, v[81].c_str());
							break;
						case 1869: strcpy(szdata, v[82].c_str());
							break;
						case 1870: strcpy(szdata, v[83].c_str());
							break;
						case 1875: strcpy(szdata, v[84].c_str());
							break;
						case 1895: strcpy(szdata, v[85].c_str());
							break;
						case 1915: strcpy(szdata, v[86].c_str());
							break;
						case 1995: strcpy(szdata, v[87].c_str());
							break;
						case 1996: strcpy(szdata, v[88].c_str());
							break;
						case 2001: strcpy(szdata, v[89].c_str());
							break;
						case 2021: strcpy(szdata, v[90].c_str());
							break;
						case 2041: strcpy(szdata, v[91].c_str());
							break;
						case 2091: strcpy(szdata, v[92].c_str());
							break;
						case 2092: strcpy(szdata, v[93].c_str());
							break;
						case 2095: strcpy(szdata, v[94].c_str());
							break;
						case 2115: strcpy(szdata, v[95].c_str());
							break;
						case 2121: strcpy(szdata, v[96].c_str());
							break;
						case 2124: strcpy(szdata, v[97].c_str());
							break;
						case 2130: strcpy(szdata, v[98].c_str());
							break;
						case 2132: strcpy(szdata, v[99].c_str());
							break;
						case 2182: strcpy(szdata, v[100].c_str());
							break;
						case 2183: strcpy(szdata, v[101].c_str());
							break;
						case 2186: strcpy(szdata, v[102].c_str());
							break;
						case 2206: strcpy(szdata, v[103].c_str());
							break;
						case 2212: strcpy(szdata, v[104].c_str());
							break;
						case 2215: strcpy(szdata, v[105].c_str());
							break;
						case 2221: strcpy(szdata, v[106].c_str());
							break;
						case 2223: strcpy(szdata, v[107].c_str());
							break;
						case 2273: strcpy(szdata, v[108].c_str());
							break;
						case 2274: strcpy(szdata, v[109].c_str());
							break;
						case 2277: strcpy(szdata, v[110].c_str());
							break;
						case 2297: strcpy(szdata, v[111].c_str());
							break;
						case 2303: strcpy(szdata, v[112].c_str());
							break;
						case 2306: strcpy(szdata, v[113].c_str());
							break;
						case 2312: strcpy(szdata, v[114].c_str());
							break;
						case 2314: strcpy(szdata, v[115].c_str());
							break;
						case 2364: strcpy(szdata, v[116].c_str());
							break;
						case 2365: strcpy(szdata, v[117].c_str());
							break;
						case 2368: strcpy(szdata, v[118].c_str());
							break;
						case 2388: strcpy(szdata, v[119].c_str());
							break;
						case 2394: strcpy(szdata, v[120].c_str());
							break;
						case 2397: strcpy(szdata, v[121].c_str());
							break;
						case 2403: strcpy(szdata, v[122].c_str());
							break;
						case 2405: strcpy(szdata, v[123].c_str());
							break;
						case 2455: strcpy(szdata, v[124].c_str());
							break;
						case 2456: strcpy(szdata, v[125].c_str());
							break;
						case 2459: strcpy(szdata, v[126].c_str());
							break;
						case 2479: strcpy(szdata, v[127].c_str());
							break;
						case 2485: strcpy(szdata, v[128].c_str());
							break;
						case 2488: strcpy(szdata, v[129].c_str());
							break;
						case 2494: strcpy(szdata, v[130].c_str());
							break;
						case 2496: strcpy(szdata, v[131].c_str());
							break;
						case 2576: strcpy(szdata, v[132].c_str());
							break;
						case 2581: strcpy(szdata, v[133].c_str());
							break;
						case 2585: strcpy(szdata, v[134].c_str());
							break;
						case 2665: strcpy(szdata, v[135].c_str());
							break;
						case 2670: strcpy(szdata, v[136].c_str());
							break;
						case 2674: strcpy(szdata, v[137].c_str());
							break;
						case 2754: strcpy(szdata, v[138].c_str());
							break;
						case 2759: strcpy(szdata, v[139].c_str());
							break;
						case 2763: strcpy(szdata, v[140].c_str());
							break;
						case 2783: strcpy(szdata, v[141].c_str());
							break;
						case 2784: strcpy(szdata, v[142].c_str());
							break;
						case 2788: strcpy(szdata, v[143].c_str());
							break;
						case 2808: strcpy(szdata, v[144].c_str());
							break;
						case 2809: strcpy(szdata, v[145].c_str());
							break;
						case 2813: strcpy(szdata, v[146].c_str());
							break;
						case 2833: strcpy(szdata, v[147].c_str());
							break;
						case 2834: strcpy(szdata, v[148].c_str());
							break;
						case 2838: strcpy(szdata, v[149].c_str());
							break;
						case 2858: strcpy(szdata, v[150].c_str());
							break;
						case 2859: strcpy(szdata, v[151].c_str());
							break;
						case 2863: strcpy(szdata, v[152].c_str());
							break;
						case 2883: strcpy(szdata, v[153].c_str());
							break;
						case 2884: strcpy(szdata, v[154].c_str());
							break;
						case 2888: strcpy(szdata, v[155].c_str());
							break;
						case 2908: strcpy(szdata, v[156].c_str());
							break;
						case 2909: strcpy(szdata, v[157].c_str());
							break;
						case 2913: strcpy(szdata, v[158].c_str());
							break;
						case 2933: strcpy(szdata, v[159].c_str());
							break;
						case 2934: strcpy(szdata, v[160].c_str());
							break;
						case 2938: strcpy(szdata, v[161].c_str());
							break;
						case 2958: strcpy(szdata, v[162].c_str());
							break;
						case 2959: strcpy(szdata, v[163].c_str());
							break;
						case 2963: strcpy(szdata, v[164].c_str());
							break;
						case 2983: strcpy(szdata, v[165].c_str());
							break;
						case 2984: strcpy(szdata, v[166].c_str());
							break;
						case 2988: strcpy(szdata, v[167].c_str());
							break;
						case 3008: strcpy(szdata, v[168].c_str());
							break;
						case 3009: strcpy(szdata, v[169].c_str());
							break;
						default:
							break;
						}
					}
				}
				//FreeLibrary(hdllInst);
				return stauts_df03ed;
			}
		}
	}
}
int _stdcall iW_DF03EDInfo(HANDLE hdev, int record, char* szdata, int npos, int nlen, int nstyle)
{
	W_ReadCardLog("EVENT iW_DF03EDInfo START");
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	HDDTYPE = atoi(hddtype);
	if (HDDTYPE == 3)
	{
		/*HMODULE hdllInst = LoadLibraryA(CAPDLL);*/
		if (HIns_CAP == NULL)
		{
			return -1801;
		}
		else
		{
			w_df03ed df03ed = (w_df03ed)GetProcAddress(HIns_CAP, "iW_DF03EDInfo");
			if (df03ed == NULL)
			{
				//FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				int stauts_df03ed = df03ed(hdev, record, szdata, npos, nlen, nstyle);
				//FreeLibrary(hdllInst);
				return stauts_df03ed;
			}
		}
	}
	if (HDDTYPE == 2)
	{
		/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
		if (HIns_WQ == NULL)
		{
			return -1801;
		}
		else
		{
			//readEDinfo readED = (readEDinfo)GetProcAddress(hdllInst, "ReadEDFileInfo");
			writeEDinfo writeED = (writeEDinfo)GetProcAddress(HIns_WQ, "WriteEDFileInfo");
			//if ((readED == NULL)||(writeED==NULL))
			if (writeED == NULL)
			{
				//FreeLibrary(hdllInst);
				return -1701;
			}
			else
			{
				//char outMsg[65535] = { 0 };
				char errMsg[1024] = { 0 };
				int ret = writeED(szdata, errMsg);
				return ret;
			}
		}
	}
}
int _stdcall SM3Digest(HANDLE hdev, BYTE* pbdata, int len, BYTE* pbhash, BYTE* pbhashlen)
{
	return 0;
}
int _stdcall VerifyPin(HANDLE hdev, char* szpin, BYTE* pwdretry)
{
	return 0;

}
int _stdcall SM2SignHash(HANDLE hdev, BYTE* pbdata, int len, BYTE* pbhash, BYTE* pbhashlen)
{
	return 0;
}
int _stdcall IReader_GetDeviceCSN(HANDLE hdev, char* info)
{
	return 0;
}
int _stdcall iReader_SAM_Public(HANDLE hdev, char* info)
{
	return 0;
}
int _stdcall iReader_GetLastEEIndex(HANDLE hdev)
{
	return 0;
}
int _stdcall iReader_GetLastEDIndex(HANDLE hdev)
{
	return 0;
}
int _stdcall LockPersonalInfo(HANDLE hdev)
{
	return -2;
}

#pragma endregion

#pragma region �����ۺ϶����ӿ�

int _stdcall XDT_GetHisInfo(HANDLE hdev, char* cardno, long* ye, char* xm, char* xb, char* csrq, char* sfzhm)
{
	return -2;
}
//�����Ǿ���̬��ӿں�������������������������Ϳ۷�
//����
long WINAPI XDT_BaseInfo(BASEINFO *info)
{
	//W_ReadCardLog("EVENT ���ú���XDT_BaseInfo��ʼ");
	BASEINFO _info;
	int op = OpenCom();
	long _uid = -1;
	if (op != 0)
	{
		return -1;
	}
	else
	{
		{
			int query_st = CapNBQueryCard(&_uid);
			if (query_st != 0)
			{
				return -2;
			}
			else
			{
				Sleep(T);
				CUSTOMERINFO custinfo;
				//����
				int getinfo_st = CapGetNBCardInfo(&custinfo);
				if (getinfo_st != 0)
				{
					return -3;
				}
				else
				{
					strcpy(info->CardASN, custinfo.CardASN);
					info->CardClass = custinfo.CardClass;
					strcpy(info->CityCardNo, custinfo.CityCardNo);
					info->CustomerID = custinfo.CustomerID;
					info->CardSN = custinfo.CardSN;
					info->Status = custinfo.Status;
					info->SubType = custinfo.SubType;
					info->Ye = custinfo.Ye;
					info->OpCount = custinfo.OpCount;
					strcpy(info->Name, custinfo.Name);
					strcpy(info->ValidDate, custinfo.ValidDate);
					CloseCom();
					//�������񽡿����ӿ�
					Sleep(T);
					HANDLE hdev = opendevice(0);

					if (hdev != (HANDLE)0)
					{
						return -4;
					}
					else
					{
						char _atr[64] = { 0 };
						Sleep(T);

						long pw1_st = PowerOn(hdev, 1, _atr);
						Sleep(T);
						long pw3_st = PowerOn(hdev, 3, _atr);

						if ((pw1_st != 0) || (pw3_st != 0))
						{
							return -5;
						}
						else
						{
							char _sfzh[18 + 1] = { 0 };
							char _xm[30 + 1] = { 0 };
							char _xb[2 + 1] = { 0 };
							char _mz[2 + 1] = { 0 };
							char _csrq[8 + 1] = { 0 };
							//��ȡ���֤��Ϣ
							Sleep(T);
							iR_DDF1EF06Info(hdev, _xm, _xb, _mz, _csrq, _sfzh);
							int len = strlen(_sfzh);
							if (len == 18)
							{
								strcpy(info->IdCardNo, _sfzh);
								std::string str_sfz(_sfzh);
								string str_sex = str_sfz.substr(16, 1);
								string str_csrq = str_sfz.substr(6, 4);
								int sex = (stoi(str_sex) % 2) == 0 ? 2 : 1;
								SYSTEMTIME _st = { 0 };
								GetLocalTime(&_st);
								char ts[24];
								sprintf(ts, "%d", _st.wYear);
								int age = stoi(ts) - stoi(str_csrq);
								info->Sex = sex;
								info->Age = age;
							}
							//��ȡ��ַ��Ϣ
							char dzlb1[3] = { 0 };
							char dz1[128] = { 0 };
							char dzlb2[3] = { 0 };
							char dz2[128] = { 0 };
							iR_DF01EF05Info(hdev, dzlb1, dz1, dzlb2, dz2);
							strcpy(info->Address1, dz1);
							strcpy(info->Address, dz2);
							return 0;
						}
					}
				}


			}
		}
	}
}
//�۷�
long WINAPI XDT_SetCardInfo(long objNo, long opFare, LPSTR TradeRecNo, LPSTR jyDT, LPSTR psamID, long *psamJyNo, LPSTR tac)
{
	//W_ReadCardLog("EVENT ���ú���XDT_SetCardInfo");
	char info[128] = { 0 };
	sprintf(info, "PARA objNo:%ld,opFare:%ld,TradeRecNo:%s,jyDT:%s", objNo, opFare, TradeRecNo, jyDT);
	//W_ReadCardLog(info);
	long _uid = 0;
	long ret_qcard = CapNBQueryCard(&_uid);
	//W_ReadCardLog("EVENT ����CapNBQueryCard����");
	if (ret_qcard != 0)
	{
		//W_ReadCardLog("ERROR -1 Ѱ��ʧ��");
		return -1;
	}
	else
	{
		if (VerifiBlackCard_UID(_uid) != 0)
		{
			return -777;
		}
		else
		{
			//�Կ۷�JSON����ֵ
			Json::Value Charging;
			Json::FastWriter fw;
			//���ö�����������ȡ�˻����
			Sleep(T);

			CUSTOMERINFO custinfo;
			long ret_getcard = CapGetNBCardInfo(&custinfo);
			//W_ReadCardLog("EVENT ���ú���CapGetNBCardInfo����");
			if (ret_getcard != 0)
			{
				//W_ReadCardLog("ERROR ����ʧ��");
				return ret_getcard;
			}
			else
			{
				long ye = custinfo.Ye;
				//�жϿ�������Ƿ���ڿ۷ѽ��
				if (ye < opFare)
				{
					//W_ReadCardLog("ERROR -11 �������С�ڿ۷ѽ��");
					return -11;
				}
				else
				{
					Charging["Oddfare"] = ye;
					string str_asn(custinfo.CardASN);
					//CARDASN��ʽ����
					string real_asn = str_asn.substr(4, strlen(custinfo.CardASN) - 6);
					char *str_temp;
					__int64 itemp = _strtoi64(real_asn.c_str(), &str_temp, 16);
					Charging["CardNo"] = std::to_string(itemp);
					Charging["OpCount"] = custinfo.OpCount;
					Charging["CustomerId"] = std::to_string(custinfo.CustomerID);
				}
			}
			//Ϊ���ٿ۷��쳣���ڲ�������ԭʼ����֮�����߳�����һС��ʱ��
			Sleep(T);

			int _redix = 10;
			char c_psamID[24] = { 0 };
			char c_tac[24] = { 0 };
			long _psamJyNo = 0;
			//��ʼ�۷�
			long ret_setcard = CapSetNBCardInfo_SLYY(objNo, _uid, opFare, jyDT, c_psamID, &_psamJyNo, c_tac, _redix);
			//W_ReadCardLog("EVENT ���ú���CapSetNBCardInfo_SLYY����");
			strcpy(psamID, c_psamID);
			*psamJyNo = _psamJyNo;
			strcpy(tac, c_tac);
			Charging["objNo"] = objNo;
			Charging["uid"] = _uid;
			Charging["opfare"] = opFare;
			Charging["psamId"] = c_psamID;
			Charging["psamJyNo"] = _psamJyNo;
			Charging["TAC"] = c_tac;
			Charging["Ret"] = ret_setcard;
			Charging["Upload"] = 0;
			//���ӽ��׼�¼��ˮ�����
			Charging["TradeRecNo"] = TradeRecNo;
			//������ʱ���ʽ
			std::string str_dt(jyDT);
			std::string str_trunce;
			while (str_dt.find("-") != -1)
			{
				str_trunce = str_dt.replace(str_dt.find("-"), 1, "");
			}
			while (str_dt.find(":") != -1)
			{
				str_trunce = str_dt.replace(str_dt.find(":"), 1, "");
			}
			while (str_dt.find(" ") != -1)
			{
				str_trunce = str_dt.replace(str_dt.find(" "), 1, "");
			}
			Charging["opDatetime"] = str_trunce.c_str();

			//����д���ı�������д��ԭʼ�ĵ�Ŀ¼��
			//W_ReadCardLog("EVENT ��ʼд����ϴ�����");
			std::string jsonstr = fw.write(Charging);
			const char* org_path = "./Log//ORG";
			if (_access(org_path, 0) == -1)
			{
				_mkdir(org_path);
			}
			SYSTEMTIME st = { 0 };
			GetLocalTime(&st);
			char filename[64] = { 0 };
			sprintf(filename, "./Log//ORG//ORG_%d%02d%02d.dat", st.wYear, st.wMonth, st.wDay);
			WriteInFile(filename, jsonstr);
			//ͬʱд��һ�ݵ�Ԥ����Ŀ¼
			const char* pre_path = "./Log//Pre";
			if (_access(pre_path, 0) == -1)
			{
				_mkdir(pre_path);
			}
			char pre_filename[64] = { 0 };
			sprintf(pre_filename, "./Log//Pre//Pre_%d%02d%02d.dat", st.wYear, st.wMonth, st.wDay);
			WriteInFile(pre_filename, jsonstr);
			/*std::thread t(OpFile);
			t.detach();*/
			OpFile();
			//W_ReadCardLog("EVENT ���ú���OpFile����");
			return ret_setcard;
		}
	}
}
long WINAPI XDT_BaseInfo_Json(char* _json, char* _name, long *UID)
{
	BASEINFO _info;
	Json::Value root;
	Json::FastWriter fw;
	int op = OpenCom();
	//long _uid = -1;
	if (op != 0)
	{
		return -1;
	}
	else
	{
		{
			int query_st = CapNBQueryCard(UID);	//ͬ��
			//int query_st = CapNBQueryCard_NoVerify(UID);	//ר��Ϊ����ҽԺ�ṩ�ķ���,����֤������
			if (query_st != 0)
			{
				CloseCom();
				return -2;
			}
			else
			{
				//UID = _uid;
				Sleep(T);
				CUSTOMERINFO custinfo;
				//����
				int getinfo_st = CapGetNBCardInfo(&custinfo);
				if (getinfo_st != 0)
				{
					CloseCom();
					return -3;
				}
				else
				{
					root["CardASN"] = custinfo.CardASN;
					root["CardClass"] = custinfo.CardClass;
					root["CityCardNo"] = custinfo.CityCardNo;
					root["CustomerID"] = custinfo.CustomerID;
					root["CardSN"] = custinfo.CardSN;
					root["Status"] = custinfo.Status;
					root["SubType"] = custinfo.SubType;
					root["Ye"] = custinfo.Ye;
					root["OpCount"] = custinfo.OpCount;
					strcpy(_name, custinfo.Name);
					//root["Name"] = custinfo.Name;
					root["ValidDate"] = custinfo.ValidDate;
					CloseCom();
					//�������񽡿����ӿ�
					Sleep(T);
					HANDLE hdev = opendevice(0);

					if (hdev != (HANDLE)0)
					{
						return -4;
					}
					else
					{
						char _atr[64] = { 0 };
						Sleep(T);

						long pw1_st = PowerOn(hdev, 1, _atr);
						Sleep(T);
						long pw3_st = PowerOn(hdev, 3, _atr);
						if ((pw1_st != 0) || (pw3_st != 0))
						{

							return -5;
						}
						else
						{
							char _sfzh[18 + 1] = { 0 };
							char _xm[30 + 1] = { 0 };
							char _xb[2 + 1] = { 0 };
							char _mz[2 + 1] = { 0 };
							char _csrq[8 + 1] = { 0 };
							Sleep(T);

							iR_DDF1EF06Info(hdev, _xm, _xb, _mz, _csrq, _sfzh);
							int len = strlen(_sfzh);
							if (len == 18)
							{
								root["IdCardNo"] = _sfzh;

								std::string str_sfz(_sfzh);
								string str_sex = str_sfz.substr(16, 1);
								string str_csrq = str_sfz.substr(6, 4);
								int sex = (stoi(str_sex) % 2) == 0 ? 2 : 1;
								SYSTEMTIME _st = { 0 };
								GetLocalTime(&_st);
								char ts[24];
								sprintf(ts, "%d", _st.wYear);
								int age = stoi(ts) - stoi(str_csrq);
								root["Sex"] = sex;
								root["Age"] = age;
							}

						}
					}
				}


			}
		}
	}
	strcpy(_json, fw.write(root).data());
	//��������
	int _wcsLen = ::MultiByteToWideChar(CP_UTF8, NULL, _json, strlen(_json), NULL, 0);
	//����ռ�Ҫ��'\0'�����ռ䣬MultiByteToWideChar�����'\0'�ռ�
	wchar_t* _wszString = new wchar_t[_wcsLen + 1];
	//ת��
	::MultiByteToWideChar(CP_UTF8, NULL, _json, strlen(_json), _wszString, _wcsLen);
	//������'\0'
	_wszString[_wcsLen] = '\0';
	_bstr_t _b(_wszString);
	char *_rev_temp = _b;
	strcpy(_json, _b);
	return 0;
}
//��ȡɨ��ǹsocketIP��ַ
LPSTR WINAPI GetIPScanner()
{
	LPSTR ipaddr = new char[20];
	GetPrivateProfileStringA("SCNNER", "IP", "NULL", ipaddr, 20, iniFileName);
	return ipaddr;
}
//��ȡɨ��ǹsocket �˿�
short WINAPI GetSCANNERPORT()
{
	
	short port;
	port = GetPrivateProfileIntA("SCNNER", "PORT", -1, iniFileName);
	return port;
}
// ����
short WINAPI DCBEEP(unsigned short msec)
{
	HMODULE HINS = LoadLibraryA("dcrf32.dll");
	dcinit init = (dcinit)GetProcAddress(HINS, "dc_init");
	HANDLE dev = init(100, 9600);
	dc_beep beep = (dc_beep)GetProcAddress(HINS, "dc_beep");
	int ret = beep(dev, 10);
	dc_exit dcexit = (dc_exit)GetProcAddress(HINS, "dc_exit");
	ret = dcexit(dev);
	return ret;
}
LPSTR WINAPI GetComInputInfo_Temp()
{
	/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
	if (HIns_WQ == NULL)
	{
		return NULL;
	}
	else
	{
		sendscancmd scan = (sendscancmd)GetProcAddress(HIns_WQ, "SendScanCmd");
		char outmsg[1024] = { 0 };
		char errmsg[1024] = { 0 };
		int ret = scan(outmsg, errmsg);
		if (ret == 0)
		{
			return outmsg;
		}
		else
		{
			return NULL;
		}
	}
}
int WINAPI test1(int a, int b)
{
	return a + b;
}
int __stdcall GetPersionalInfo_wq(int type, char* msgJson)
{
	W_ReadCardLog("EVENT GetPersionalInfo START");
	// JudgeHDDType();

	if (type == 1)
	{
		Json::Value root;
		Json::FastWriter fw;

		char outMsg[1024] = { 0 };
		if (HDDTYPE == 1)
		{
			HANDLE hdev = OpenDevice(0);

			if (hdev != (HANDLE)0)
			{
				return -1;
			}
			else
			{
				char _atr[64] = { 0 };
				Sleep(T);

				long pw1_st = PowerOn(hdev, 1, _atr);
				Sleep(T);
				long pw3_st = PowerOn(hdev, 3, _atr);
				if ((pw1_st != 0) || (pw3_st != 0))
				{
					return -2;
				}
				else
				{
					char _sfzh[18 + 1] = { 0 };
					char _xm[30 + 1] = { 0 };
					char _xb[2 + 1] = { 0 };
					char _mz[2 + 1] = { 0 };
					char _csrq[8 + 1] = { 0 };
					Sleep(T);

					int ret = iR_DDF1EF06Info(hdev, _xm, _xb, _mz, _csrq, _sfzh);
					if ((ret == 0) && (strlen(_xm) > 0) && (strlen(_sfzh) > 0))
					{
						root["flag"] = 1;
					}
					else
					{
						root["flag"] = 0;
					}
					root["content"]["papersNum"] = _sfzh;
					root["content"]["userName"] = _xm;
					Sleep(T);
					char _kyxq[100] = { 0 };
					char _tel1[20] = { 0 };
					char _tel2[20] = { 0 };
					char _zffs1[20] = { 0 };
					char _zffs2[20] = { 0 };
					char _zffs3[20] = { 0 };
					iR_DDF1EF08Info(hdev, _kyxq, _tel1, _tel2, _zffs1, _zffs2, _zffs3);
					if (strlen(_tel1) > 0)
					{
						root["content"]["telephone"] = _tel1;
					}
					else
					{
						root["content"]["telephone"] = _tel2;
					}
					Sleep(T);
					char _dzlb1[20] = { 0 };
					char _dz1[100] = { 0 };
					char _dzlb2[20] = { 0 };
					char _dz2[100] = { 0 };
					iR_DF01EF05Info(hdev, _dzlb1, _dz1, _dzlb2, _dz2);
					if (strlen(_dz1) > 0)
					{
						root["content"]["patientAddr"] = _dz1;
					}
					else
					{
						root["content"]["patientAddr"] = _dz2;
					}
					string strMsg = fw.write(root);
					strcpy(msgJson, strMsg.c_str());
				}
				return 0;
			}
		}
		if (HDDTYPE == 2)
		{


			/*HMODULE hdllInst = LoadLibraryA(CONDLL);*/
			if (HIns_WQ == NULL)
			{
				return -1801;
			}
			else
			{
				readcardinfo ef05 = (readcardinfo)GetProcAddress(HIns_WQ, "ReadCardInfo");
				if (ef05 == NULL)
				{
					//FreeLibrary(hdllInst);
					return -1701;
				}
				else
				{
					char errMsg[1024] = { 0 };
					int ret = ef05(outMsg, errMsg);
					if (ret == 0) //�����񽡿����ɹ�
					{
						std::vector<std::string> vec;
						string strOutMsg(outMsg);
						my_split(strOutMsg, c_spliter, v);
						char sfzh[20] = { 0 };
						strcpy(sfzh, vec[5].c_str());
						if (strlen(sfzh) > 14)
						{
							//�������֤�Ų�ѯ������Ϣ
							char outJson[1024] = { 0 };
							long cardtype = 1;	//ʵ�忨
							long rt = GetCusInfoByUnion(cardtype, sfzh, msgJson);
							return rt;
						}
						else
						{
							W_ReadCardLog("ERROR	GetPersionalInfo	���֤�����ʽ����ȷ");

							return -2;
						}
					}
					else
					{
						W_ReadCardLog("ERROR	GetPersionalInfo	����ReadCardInfo�ӿڵ����쳣");

						return -1;
					}
				}
			}
		}
	}
	if (type == 2)
	{
		char qrcode[1024] = { 0 };
		int ret = GetComInputInfo(qrcode);
		string content_kh(qrcode);
		if (strlen(qrcode) > 10)
		{
			string searchtype = "search";
			char req_resv[2048];
			LPSTR req_ip;
			req_ip = GetValueInIni("MIS", "BCNIP", iniFileName);
			short _port = GetPrivateProfileIntA("MIS", "BCNPORT", 80, iniFileName);
			//���岢��ʼ��Json����
			Json::Value sendvalue;
			//string content(_info);
			string orgcode(GetValueInIni("MIS", "ORGCODE", iniFileName));
			string serialNo(GetValueInIni("MIS", "SERIALNO", iniFileName));
			sendvalue["content"] = content_kh;
			sendvalue["organizationCode"] = orgcode;
			sendvalue["serialNumber"] = serialNo;
			sendvalue["method"] = searchtype;
			string sendJson = sendvalue.toStyledString();
			char _send_buff[2048] = { 0 };
			strcpy(_send_buff, sendJson.c_str());
			char logtmp[2048];
			sprintf(logtmp, "�������������Ϊ�� %s", _send_buff);
			W_ReadCardLog(logtmp);
			//��������
			long ret_sendpost = SendPostRequest(req_ip, _port, _send_buff, req_resv);
			if (0 == ret_sendpost)
			{
				char _rev_temp[2048] = { 0 };
				TransCharacter(req_resv, _rev_temp);
				//��ȡjson
				string str_rev(_rev_temp);
				string json_rel;
				int json_bg = str_rev.find_first_of("{", 0);
				int json_end = str_rev.find_last_of("}");
				if (json_end > json_bg)
				{
					json_rel = str_rev.substr(json_bg, json_end - json_bg + 1);
					W_ReadCardLog(json_rel.c_str());
					strcpy(msgJson, json_rel.c_str());
					return 0;
				}
				else
				{
					W_ReadCardLog("ERROR	GetPersionalInfo	ƽ̨���ز�����ʽ����ȷ");

					return -1;
				}
			}
			else
			{
				W_ReadCardLog("ERROR	GetPersionalInfo	��Ϣ��ѯ�ӿ�����ʧ��");

				return -2;
			}
		}
		else
		{
			W_ReadCardLog("ERROR	GetPersionalInfo	ɨ��ʧ�ܻ���ֵ��ʽ����");
			return -3;
		}
	}
	if (type==3)
	{
		if (HIns_WQ==NULL)
		{
			return 101;
		}
		else
		{
			r_pinfo rpinfo = (r_pinfo)GetProcAddress(HIns_WQ, "ReadPersonalInfo");
			char outmsg[1024] = { 0 };
			char errmsg[1024] = { 0 };
			int ret = rpinfo(3, outmsg, errmsg);
			if (ret==0)
			{
				std::vector<std::string> vec;
				string strout(outmsg);
				Json::Value root;
				Json::FastWriter fw;
				my_split(strout, c_spliter, vec);
				root["code"] = "ROOOOO";
				root["content"]["data"]["papersNum"] = vec[1].c_str();
				root["content"]["data"]["userName"] = vec[2].c_str();
				root["content"]["data"]["patientAddr"] = vec[5].c_str();
				root["desc"] = "���ݲ�ѯ�ɹ�";
				root["flag"] = 1;
				string strjson = fw.write(root);
				strcpy(msgJson, strjson.c_str());
			}
			else
			{
				return 103;
			}
		}
	}
	if (type==4)
	{
		if (HIns_WQ == NULL)
		{
			return 101;
		}
		else
		{
			r_pinfo rpinfo = (r_pinfo)GetProcAddress(HIns_WQ, "ReadPersonalInfo");
			char outmsg[1024] = { 0 };
			char errmsg[1024] = { 0 };
			int ret = rpinfo(4, outmsg, errmsg);
			if (ret == 0)
			{
				std::vector<std::string> vec;
				string strout(outmsg);
				Json::Value root;
				Json::FastWriter fw;
				my_split(strout, c_spliter, vec);
				root["code"] = "ROOOOO";
				root["content"]["data"]["papersNum"] = vec[5].c_str();
				root["content"]["data"]["userName"] = vec[0].c_str();
				root["content"]["data"]["patientAddr"] = vec[4].c_str();
				root["desc"] = "���ݲ�ѯ�ɹ�";
				root["flag"] = 1;
				string strjson = fw.write(root);
				strcpy(msgJson, strjson.c_str());
			}
			else
			{
				return 103;
			}
		}
	}
}
string UTF8ToGB(const char* str)
{
	string result;
	WCHAR *strSrc;
	LPSTR szRes;

	int i = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
	strSrc = new WCHAR[i + 1];
	MultiByteToWideChar(CP_UTF8, 0, str, -1, strSrc, i);

	i = WideCharToMultiByte(CP_ACP, 0, strSrc, -1, NULL, 0, NULL, NULL);
	szRes = new CHAR[i + 1];
	WideCharToMultiByte(CP_ACP, 0, strSrc, -1, szRes, i, NULL, NULL);

	result = szRes;
	delete[]strSrc;
	delete[]szRes;
	return result;
}
LPSTR WINAPI GetPersionalInfo_temp_wq(int type)
{
	W_ReadCardLog("EVENT GetPersionalInfo_temp START");

	// JudgeHDDType();

	if (type == 1)
	{
		W_ReadCardLog("EVENT GetPersionalInfo_temp Search type=1");
		Json::Value root;
		Json::FastWriter fw;
		int ret = -1;
		char* outMsg = new char[512];


		//HMODULE hdllInst = LoadLibraryA(CONDLL);
		if (HIns_WQ == NULL)
		{
			W_ReadCardLog("ERROR	GetPersionalInfo_temp	δ������������������");
			return NULL;
		}
		else
		{
			//����W2160��������Ϣ��ҪPSAM��
			//2019��12��3��14:18:59 ͨ����ȡ���֤�ź��ѯ��Ϣ
			readcardinfo ef05 = (readcardinfo)GetProcAddress(HIns_WQ, "ReadCardInfo");
			if (ef05 == NULL)
			{
				//FreeLibrary(hdllInst);
				W_ReadCardLog("ERROR	GetPersionalInfo_temp	����ReadCardInfo�����쳣");
				return NULL;
			}
			else
			{
				char errMsg[1024] = { 0 };
				ret = ef05(outMsg, errMsg);
				/*char log[1024];
				sprintf(log, "DF1EF06 ����״̬��%d,������Ϣ��%s��������Ϣ��%s", ret, outMsg, errMsg);
				W_ReadCardLog(log);*/
				if (ret == 0) //�����ɹ�
				{
					RTYPE = 1;
					std::vector<std::string> vec;
					string strOutMsg(outMsg);
					my_split(strOutMsg, c_spliter, vec);
					char sfzh[20] = { 0 };
					strcpy(sfzh, vec[5].c_str());
					if (strlen(sfzh) > 14)
					{
						//�������֤�Ų�ѯ������Ϣ
						char outJson[1024] = { 0 };
						long cardtype = 1;	//ʵ�忨
						long rt = GetCusInfoByUnion(cardtype, sfzh, outMsg);
						if (rt == 0)
						{
							return outMsg;
						}
						else
						{
							W_ReadCardLog("ERROR	GetPersionalInfo_temp	��ѯ������Ϣʧ��");

							return NULL;
						}
					}
					else
					{
						W_ReadCardLog("ERROR	GetPersionalInfo_temp	���֤���벻�Ϲ�");

						return NULL;
					}
				}
				else
				{
					W_ReadCardLog("ERROR	GetPersionalInfo_temp	�����豸�����񽡿���ʧ��");

					return NULL;
				}
			}
		}

	}
	if (type == 2)
	{
		char qrcode[1024] = { 0 };
		int ret = GetComInputInfo(qrcode);
		string content_kh(qrcode);
		if (strlen(qrcode) > 10)
		{


			string searchtype = "search";
			char req_resv[2048];
			LPSTR req_ip;
			req_ip = GetValueInIni("MIS", "BCNIP", iniFileName);
			short _port = GetPrivateProfileIntA("MIS", "BCNPORT", 80, iniFileName);
			//���岢��ʼ��Json����
			Json::Value sendvalue;
			//string content(_info);
			string orgcode(GetValueInIni("MIS", "ORGCODE", iniFileName));
			string serialNo(GetValueInIni("MIS", "SERIALNO", iniFileName));
			sendvalue["content"] = content_kh;
			sendvalue["organizationCode"] = orgcode;
			sendvalue["serialNumber"] = serialNo;
			sendvalue["method"] = searchtype;
			sendvalue["dataType"] = "010115";
			string sendJson = sendvalue.toStyledString();
			char _send_buff[2048] = { 0 };
			strcpy(_send_buff, sendJson.c_str());
			char logtmp[2048];
			sprintf(logtmp, "�������������Ϊ�� %s", _send_buff);
			W_ReadCardLog(logtmp);
			//��������
			long ret_sendpost = SendPostRequest(req_ip, _port, _send_buff, req_resv);
			if (0 == ret_sendpost)
			{
				char _rev_temp[2048] = { 0 };
				TransCharacter(req_resv, _rev_temp);
				//��ȡjson
				string str_rev(_rev_temp);
				string json_rel;
				int json_bg = str_rev.find_first_of("{", 0);
				int json_end = str_rev.find_last_of("}");
				if (json_end > json_bg)
				{
					json_rel = str_rev.substr(json_bg, json_end - json_bg + 1);
					char* msgJson = new char[1024];
					//char msgJson[1024] = { 0 };
					W_ReadCardLog(json_rel.c_str());
					strcpy(msgJson, json_rel.c_str());
					return msgJson;
				}
				else
				{
					W_ReadCardLog("ERROR	GetPersionalInfo_temp	��ά���ѯƽ̨������Ϣ��ʽ����ȷ");

					return NULL;
				}
			}
			else
			{
				W_ReadCardLog("ERROR	GetPersionalInfo_temp	��ά���ѯPOST����ʧ��");

				return NULL;
			}
		}
		else
		{
			W_ReadCardLog("ERROR	GetPersionalInfo_temp	ɨ��ʧ�ܻ���ֵ��ʽ����");
			return NULL;
		}
	}
	if (type == 3)
	{
		if (HIns_WQ == NULL)
		{
			return NULL;
		}
		else
		{
			r_pinfo rpinfo = (r_pinfo)GetProcAddress(HIns_WQ, "ReadPersonalInfo");
			char outmsg[1024] = { 0 };
			char errmsg[1024] = { 0 };
			int ret = rpinfo(3, outmsg, errmsg);
			if (ret == 0)
			{
				std::vector<std::string> vec;
				string strout(outmsg);
				Json::Value root;
				Json::FastWriter fw;
				my_split(strout, c_spliter, vec);
				root["code"] = "ROOOOO";
				root["content"]["data"]["papersNum"] = vec[1].c_str();
				root["content"]["data"]["userName"] = vec[2].c_str();
				root["content"]["data"]["patientAddr"] = vec[5].c_str();
				root["desc"] = "���ݲ�ѯ�ɹ�";
				root["flag"] = 1;
				string strjson = fw.write(root);
				char* msgJson = new char[512];
				strcpy(msgJson, strjson.c_str());
				return msgJson;
			}
			else
			{
				return NULL;
			}
		}
	}
	if (type == 4)
	{
		if (HIns_WQ == NULL)
		{
			return NULL;
		}
		else
		{
			r_pinfo rpinfo = (r_pinfo)GetProcAddress(HIns_WQ, "ReadPersonalInfo");
			char outmsg[1024] = { 0 };
			char errmsg[1024] = { 0 };
			int ret = rpinfo(4, outmsg, errmsg);
			if (ret == 0)
			{
				std::vector<std::string> vec;
				string strout(outmsg);
				Json::Value root;
				Json::FastWriter fw;
				my_split(strout, c_spliter, vec);
				root["code"] = "ROOOOO";
				root["content"]["data"]["papersNum"] = vec[5].c_str();
				root["content"]["data"]["userName"] = vec[0].c_str();
				root["content"]["data"]["patientAddr"] = vec[4].c_str();
				root["desc"] = "���ݲ�ѯ�ɹ�";
				root["flag"] = 1;
				string strjson = fw.write(root);
				char* msgJson = new char[512];
				strcpy(msgJson, strjson.c_str());
				return msgJson;
			}
			else
			{
				return NULL;
			}
		}
	}
}
LPSTR WINAPI GetPersionalInfo_temp_dc(int type)
{
	W_ReadCardLog("EVENT GetPersionalInfo_temp START");
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	if (type==1)
	{
		DCBEEP(10);

		HMODULE HINS = LoadLibraryA("DCHealthyCarder.dll");
		dc_open open = (dc_open)GetProcAddress(HINS, "OpenDevice");
		HANDLE dev = open(100);
		if ((long)dev>0)
		{
			W_ReadCardLog("�¿��˿ڴ򿪳ɹ�");
		}
		else
		{
			return NULL;
		}

		dc_poweron poweron = (dc_poweron)GetProcAddress(HINS, "PowerOn");
		char data[100];
		int ret = poweron(dev, 0, data);
		if (ret==0)
		{
			W_ReadCardLog("�¿���λ�ɹ�");
		}
		dc_ref05 ref05 = (dc_ref05)GetProcAddress(HINS, "iR_DDF1EF05Info");
		char klb[100];
		char gfbb[100];
		char fkmc[100];
		char fkdm[1000];
		char fkzs[10240];
		char fksj[100];
		char kh[100] = { 0 };
		char aqm[100];
		char xlh[100];
		char csdm[100];
		ret = ref05(dev, klb, gfbb, fkmc, fkdm, fkzs, fksj, kh, aqm, xlh, csdm);
		char log[100];
		sprintf(log, "�¿���EF05״̬��%d�����ţ�%s", ret, kh);
		W_ReadCardLog(log);
		dc_close dclose = (dc_close)GetProcAddress(HINS, "CloseDevice");
		dclose(dev);

		if (ret==0)
		{
			W_ReadCardLog("�¿������񽡿����ɹ�");
			if (strlen(kh) > 14)
			{
				//�������֤�Ų�ѯ������Ϣ
				char outJson[1024] = { 0 };
				long cardtype = 1;	//ʵ�忨
				char* outMsg = new char[512];
				long rt = GetCusInfoByUnion(cardtype, kh, outMsg);
				return outMsg;
			}
		}
		return NULL;
	}
	if (type == 2)
	{
		char qrcode[512] = { 0 };
		int ret = DC_SCAN(qrcode);
		string content_kh(qrcode);
		if (strlen(qrcode) > 10)
		{
			////char* msgJson = new char[1024];
			//char msgJson[512] = { 0 };
			//GetCusInfoByUnion(2, qrcode, msgJson);
			////delete[] msgJson;
			//return msgJson;
			string searchtype = "search";
			char req_resv[2048];
			LPSTR req_ip;
			req_ip = GetValueInIni("MIS", "BCNIP", iniFileName);
			short _port = GetPrivateProfileIntA("MIS", "BCNPORT", 80, iniFileName);
			//���岢��ʼ��Json����
			Json::Value sendvalue;
			//string content(_info);
			string orgcode(GetValueInIni("MIS", "ORGCODE", iniFileName));
			string serialNo(GetValueInIni("MIS", "SERIALNO", iniFileName));
			sendvalue["content"] = content_kh;
			sendvalue["organizationCode"] = orgcode;
			sendvalue["serialNumber"] = serialNo;
			sendvalue["method"] = searchtype;
			sendvalue["dataType"] = "010115";

			string sendJson = sendvalue.toStyledString();
			char _send_buff[2048] = { 0 };
			strcpy(_send_buff, sendJson.c_str());
			char logtmp[2048];
			sprintf(logtmp, "�������������Ϊ�� %s", _send_buff);
			W_ReadCardLog(logtmp);
			//��������
			long ret_sendpost = SendPostRequest(req_ip, _port, _send_buff, req_resv);
			if (0 == ret_sendpost)
			{
				char _rev_temp[2048] = { 0 };
				TransCharacter(req_resv, _rev_temp);
				//��ȡjson
				string str_rev(_rev_temp);
				string json_rel;
				int json_bg = str_rev.find_first_of("{", 0);
				int json_end = str_rev.find_last_of("}");
				if (json_end > json_bg)
				{
					json_rel = str_rev.substr(json_bg, json_end - json_bg + 1);
					
					//char msgJson[1024] = { 0 };
					char* msgJson = new char[1024];
					W_ReadCardLog(json_rel.c_str());
					strcpy(msgJson, json_rel.c_str());
					return msgJson;
				}
				else
				{
					W_ReadCardLog("ERROR	GetPersionalInfo_temp	��ά���ѯƽ̨������Ϣ��ʽ����ȷ");

					return NULL;
				}
			}
			else
			{
				W_ReadCardLog("ERROR	GetPersionalInfo_temp	��ά���ѯPOST����ʧ��");

				return NULL;
			}
		}
		else
		{
			W_ReadCardLog("ERROR	GetPersionalInfo_temp	ɨ��ʧ�ܻ���ֵ��ʽ����");
			return NULL;
		}
	}
}
int __stdcall GetPersionalInfo_dc(int type,char* datatype,char* qrcode, char* msgJson)
{
	W_ReadCardLog("EVENT GetPersionalInfo START");

	//JudgeHDDType();
	if (type == 1)
	{
		dc_open open = (dc_open)GetProcAddress(HIns_DC_HEL, "OpenDevice");
		HANDLE dev = open(100);
		
		dc_poweron poweron = (dc_poweron)GetProcAddress(HIns_DC_HEL, "PowerOn");
		char data[100];
		int ret = poweron(dev, 0, data);
		dc_ref05 ref05 = (dc_ref05)GetProcAddress(HIns_DC_HEL, "iR_DDF1EF05Info");
		char klb[100];
		char gfbb[100];
		char fkmc[100];
		char fkdm[1000];
		char fkzs[10240];
		char fksj[100];
		char kh[100];
		char aqm[100];
		char xlh[100];
		char csdm[100];
		ret = ref05(dev, klb, gfbb, fkmc, fkdm, fkzs, fksj, kh, aqm, xlh, csdm);
		dc_close dclose = (dc_close)GetProcAddress(HIns_DC_HEL, "CloseDevice");
		dclose(dev);
		// ����
		DCBEEP(10);

		if (ret == 0)
		{
			if (strlen(kh) > 14)
			{
				//�������֤�Ų�ѯ������Ϣ
				char outJson[1024] = { 0 };
				long cardtype = 1;	//ʵ�忨
				char* outMsg = new char[512];
				long rt = GetCusInfoByUnion_DataType(cardtype, kh,datatype, outMsg);
				
				strcpy(msgJson, outMsg);
				return rt;
			}
		}
	}
	if (type == 2)
	{

		/*char qrcode[512] = { 0 };
		int ret = DC_SCAN(qrcode);*/
		string content_kh(qrcode);
		if (strlen(qrcode) > 10)
		{
			char* outMsg = new char[1024];
			int status = GetCusInfoByUnion_DataType(2, qrcode,datatype, outMsg);
			strcpy(msgJson, outMsg);
			delete[] outMsg;
			return status;
			//string searchtype = "search";
			//char req_resv[2048];
			//LPSTR req_ip;
			//req_ip = GetValueInIni("MIS", "BCNIP", iniFileName);
			//short _port = GetPrivateProfileIntA("MIS", "BCNPORT", 80, iniFileName);
			////���岢��ʼ��Json����
			//Json::Value sendvalue;
			////string content(_info);
			//string orgcode(GetValueInIni("MIS", "ORGCODE", iniFileName));
			//string serialNo(GetValueInIni("MIS", "SERIALNO", iniFileName));
			//sendvalue["content"] = content_kh;
			//sendvalue["organizationCode"] = orgcode;
			//sendvalue["serialNumber"] = serialNo;
			//sendvalue["method"] = searchtype;
			//string sendJson = sendvalue.toStyledString();
			//char _send_buff[2048] = { 0 };
			//strcpy(_send_buff, sendJson.c_str());
			//char logtmp[2048];
			//sprintf(logtmp, "�������������Ϊ�� %s", _send_buff);
			//W_ReadCardLog(logtmp);
			////��������
			//long ret_sendpost = SendPostRequest(req_ip, _port, _send_buff, req_resv);
			//if (0 == ret_sendpost)
			//{
			//	char _rev_temp[2048] = { 0 };
			//	TransCharacter(req_resv, _rev_temp);
			//	//��ȡjson
			//	string str_rev(_rev_temp);
			//	string json_rel;
			//	int json_bg = str_rev.find_first_of("{", 0);
			//	int json_end = str_rev.find_last_of("}");
			//	if (json_end > json_bg)
			//	{
			//		json_rel = str_rev.substr(json_bg, json_end - json_bg + 1);
			//		W_ReadCardLog(json_rel.c_str());
			//		strcpy(msgJson, json_rel.c_str());
			//		return 0;
			//	}
			//	else
			//	{
			//		W_ReadCardLog("ERROR	GetPersionalInfo	ƽ̨���ز�����ʽ����ȷ");

			//		return -1;
			//	}
			//}
			//else
			//{
			//	W_ReadCardLog("ERROR	GetPersionalInfo	��Ϣ��ѯ�ӿ�����ʧ��");

			//	return -2;
			//}
		}
		else
		{
			W_ReadCardLog("ERROR	GetPersionalInfo	ɨ��ʧ�ܻ���ֵ��ʽ����");
			return -3;
		}
	}
}
int __stdcall GerernateEHCARD(char* json, char* outMsg)
{
	LPSTR postaddress = GetValueInIni("MIS", "POSTHCAR", iniFileName);

}
int WINAPI GetPersionalInfo(int type,char* datatype,char* qrcode,char* outmsg)
{
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	int htype = atoi(hddtype);
	switch (htype)
	{
	case 1:return GetPersionalInfo_dc(type,datatype,qrcode,outmsg);
		break;
	case 2:return GetPersionalInfo_wq(type,outmsg);
		break;
	default:
		break;
	}
}
LPSTR WINAPI GetPersionalInfo_temp(int type)
{
	char* hddtype = GetValueInIni("MIS", "HDDTYPE", iniFileName);
	int htype = atoi(hddtype);
	switch (htype)
	{
	case 1:return GetPersionalInfo_temp_dc(type);
		break;
	case 2:return GetPersionalInfo_temp_wq(type);
		break;
	default:
		break;
	}
}
// 2020��2��13��13:48:03 ���Ӹ��ݵ��ӽ�������ά���ȡ���֤����ӿ�
int __stdcall GetICNFromQRCode(int type, char* qrcode, char* outICN)
{
	string content_kh(qrcode);
	if (strlen(qrcode) > 10)
	{
		string searchtype = "search";
		char req_resv[2048];
		LPSTR req_ip;
		req_ip = GetValueInIni("MIS", "BCNIP", iniFileName);
		short _port = GetPrivateProfileIntA("MIS", "BCNPORT", 80, iniFileName);
		//���岢��ʼ��Json����
		Json::Value sendvalue;
		//string content(_info);
		string orgcode(GetValueInIni("MIS", "ORGCODE", iniFileName));
		string serialNo(GetValueInIni("MIS", "SERIALNO", iniFileName));
		sendvalue["content"] = content_kh;
		sendvalue["organizationCode"] = orgcode;
		sendvalue["serialNumber"] = serialNo;
		sendvalue["method"] = searchtype;
		sendvalue["dataType"] = "010115";
		string sendJson = sendvalue.toStyledString();
		char _send_buff[2048] = { 0 };
		strcpy(_send_buff, sendJson.c_str());
		char logtmp[2048];
		sprintf(logtmp, "�������������Ϊ�� %s", _send_buff);
		W_ReadCardLog(logtmp);
		//��������
		long ret_sendpost = SendPostRequest(req_ip, _port, _send_buff, req_resv);
		if (0 == ret_sendpost)
		{
			char _rev_temp[2048] = { 0 };
			TransCharacter(req_resv, _rev_temp);
			//��ȡjson
			string str_rev(_rev_temp);
			string json_rel;
			int json_bg = str_rev.find_first_of("{", 0);
			int json_end = str_rev.find_last_of("}");
			if (json_end > json_bg)
			{
				json_rel = str_rev.substr(json_bg, json_end - json_bg + 1);
				W_ReadCardLog(json_rel.c_str());
				//strcpy(outmsg, json_rel.c_str());
				Json::Value JsonReturn;
				Json::Reader jr;
				jr.parse(json_rel.c_str(), JsonReturn);
				string ICN = JsonReturn["content"]["data"]["papersNum"].asString();
				strcpy(outICN, ICN.c_str());
				return 0;
			}
			else
			{
				W_ReadCardLog("ERROR	GetPersionalInfo	ƽ̨���ز�����ʽ����ȷ");

				return -1;
			}
		}
		else
		{
			W_ReadCardLog("ERROR	GetPersionalInfo	��Ϣ��ѯ�ӿ�����ʧ��");

			return -2;
		}
	}
	else
	{
		return 404;
	}
}
// �¿�ɨ��֧��
int __stdcall Trans_dc(char* oprator, long opfare, char* jydt,char* outjson)
{
	W_ReadCardLog("EVENT CapSetNBCardInfo_Str START");
	// JudgeHDDType();
	char outmsg[2048] = { 0 };
	int ret = DC_SCAN(outmsg);
	if (ret == 0)
	{
		Json::Value sendvalue;
		string orgcode(GetValueInIni("MIS", "ORGCODE", iniFileName));
		string serialNo(GetValueInIni("MIS", "SERIALNO", iniFileName));
		sendvalue["organizationCode"] = orgcode;
		sendvalue["serialNumber"] = serialNo;
		sendvalue["method"] = "pay";
		//ʹ��17λʱ�����Ϊ������
		std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::system_clock::now().time_since_epoch());
		sendvalue["content"]["orderNo"] = ms.count();
		sendvalue["content"]["orderTime"] = TransDate(jydt);
		sendvalue["content"]["txnAmt"] = opfare;
		sendvalue["content"]["termId"] = atoll(GetValueInIni("MIS", "TERMID", iniFileName));//�ն˺�
		sendvalue["content"]["reqType"] = "Clinic";
		sendvalue["content"]["couponInfo"] = 0;
		sendvalue["content"]["qrNo"] = outmsg;
		sendvalue["content"]["merId"] = GetValueInIni("MIS", "MERID", iniFileName);
		sendvalue["content"]["merCatCode"] = GetValueInIni("MIS", "MERCATCODE", iniFileName);
		sendvalue["content"]["merName"] = GetValueInIni("MIS", "MERNAME", iniFileName);
		string sendJson = sendvalue.toStyledString();
		char _send_buff[1024] = { 0 };
		memcpy(_send_buff, sendJson.c_str(), 1024);
		W_ReadCardLog(_send_buff);
		//�ύ�ӿ�
		LPSTR req_ip;
		req_ip = GetValueInIni("MIS", "BCNIP", iniFileName);
		short _port = GetPrivateProfileIntA("MIS", "BCNPORT", 80, iniFileName);
		char req_resv[1024] = { 0 };
		long ret_sendpost = SendPostRequest(req_ip, _port, _send_buff, req_resv);
		if (0 == ret_sendpost)
		{
			//��ȡjson
			char _rev_temp[2048] = { 0 };
			TransCharacter(req_resv, _rev_temp);
			string str_rev(_rev_temp);
			string json_rel;
			int json_bg = str_rev.find_first_of("{", 0);
			int json_end = str_rev.find_last_of("}");
			if (json_end > json_bg)
			{
				json_rel = str_rev.substr(json_bg, json_end - json_bg + 1);
				W_ReadCardLog(json_rel.c_str());
				strcpy(outjson, json_rel.c_str());
				//����Jsonʾ����
				//{"code":"R00000","content":{"data":{"orderNo":"1558334758179","payResult":"�ɹ�","autoCode":"0","termId":"1"}},"desc":"֧���ɹ�","flag":1}
				return 0;
			}
			else
			{
				W_ReadCardLog("ERROR ������Ϣ��ʽ����");
				return -12;
			}
		}
		else
		{
			return ret_sendpost;
		}
	}
	else
	{
		return -1;
	}
}
#pragma endregion