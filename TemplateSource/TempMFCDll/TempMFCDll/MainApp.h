// Main.h : Main DLL ����ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CMainApp
// �йش���ʵ�ֵ���Ϣ������� Main.cpp
//

class CMainApp : public CWinApp
{
public:
	CMainApp();

// ��д
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
};
