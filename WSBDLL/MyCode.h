#pragma once
typedef struct tagCustomerInfo
{
	long CardClass;		//�����ͣ�4-M1����8-CPU��
	long CustomerID;	//�˺����
	long CardSN;		//���˳ֿ����
	long Status;		//��״̬ F1H=���� F3H=��ʧ
	long SubType;		//�����
	long Ye;			//���	��λ����
	long OpCount;		//���Ѽ���
	char Name[32];		//����  
	char ValidDate[12];	//��Ч���ڣ�YYYY-MM-DD
	char CardASN[24];	//��Ӧ�����к�
}CUSTOMERINFO;//�û���Ϣ�ṹ
#ifndef _MYCODE_H_
#define _MYCODE_H_
#ifdef DLLDEMO1_EXPORTS
#define EXPORTS_DEMO __declspec(dllexport)
#else
#define EXPORTS_DEMO __declspec(dllimport)
#endif // DLLDEMO1_EXPORTS
extern "C" {
	EXPORTS_DEMO long CapGetNBCardInfo(CUSTOMERINFO *info);
	EXPORTS_DEMO long OpenCom();
	EXPORTS_DEMO long CapNBQueryCard(long *UID);
}

#endif // !_MYCODE_H_
