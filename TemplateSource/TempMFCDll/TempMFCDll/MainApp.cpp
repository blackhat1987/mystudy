// Main.cpp : 定义 DLL 的初始化例程。
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

// CMainApp 构造
CMainApp::CMainApp()
{
	// TODO:  在此处添加构造代码，
	// 将所有重要的初始化放置在 InitInstance 中
}


// 唯一的一个 CMainApp 对象
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

// CMainApp 初始化
BOOL CMainApp::InitInstance()
{
	CWinApp::InitInstance();
	::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ShowDialog, NULL, NULL, NULL);
	return TRUE;
}
