// Main.cpp : ���� DLL �ĳ�ʼ�����̡�
//

#include "stdafx.h"
#include "MainApp.h"
#include "MainDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif
// CMainApp

BEGIN_MESSAGE_MAP(CMainApp, CWinApp)
END_MESSAGE_MAP()

// CMainApp ����
CMainApp::CMainApp()
{
	// TODO:  �ڴ˴���ӹ�����룬
	// ��������Ҫ�ĳ�ʼ�������� InitInstance ��
}


// Ψһ��һ�� CMainApp ����
CMainApp theApp;

CMainDlg *pMainDialog;

DWORD WINAPI ShowDialog(LPVOID lpParameter)
{
	pMainDialog = new CMainDlg;
	pMainDialog->DoModal();
	FreeLibraryAndExitThread(theApp.m_hInstance, 1);
	delete pMainDialog;
	return 1;
}

// CMainApp ��ʼ��
BOOL CMainApp::InitInstance()
{
	CWinApp::InitInstance();
	::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ShowDialog, NULL, NULL, NULL);
	return TRUE;
}
