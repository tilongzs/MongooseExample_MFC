#pragma once
#include <functional>
#include <future>

#include "Mongoose/mongoose.h"

using std::function;
using std::future;
using std::shared_ptr;

struct EventData;

class CMongooseExample_MFCDlg : public CDialogEx
{
public:
	CMongooseExample_MFCDlg(CWnd* pParent = nullptr);

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MongooseExample_MFC_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);

	struct TheadFunc
	{
		function<void()> Func;
	};
protected:
	HICON m_hIcon;

	virtual BOOL OnInitDialog();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

	LRESULT OnFunction(WPARAM wParam, LPARAM lParam);
private:
	CEdit _editRecv;
	CEdit _editPort;
	CEdit _editRemotePort;
	CButton _btnUseSSL;
	CButton _btnHTTPServer;
	CButton _btnStopHttpServer;
	CIPAddressCtrl _ipRemote;

	shared_ptr<EventData> _listenEventData = nullptr;
	shared_ptr<EventData> _currentEventData = nullptr;
	bool			_isNeedDeleteMgr = false;
	bool			_isWebsocket = false;

public:
	void AppendMsg(const WCHAR* msg);
	bool IsUseSSL();
	void OnSetCurrentEventData(shared_ptr<EventData> eventData);
	void OnDisconnectClient(mg_connection* conn);
	void OnDisconnectServer();
	void SetNeedDeleteMgr();
private:
	afx_msg void OnBtnDisconnClient();
	afx_msg void OnBtnListen();
	afx_msg void OnBtnCreatetimer();
	afx_msg void OnBtnStopListen();
	afx_msg void OnBtnConnect();
	afx_msg void OnBtnDisconnectServer();
	afx_msg void OnBtnSendMsg();
	afx_msg void OnBtnUdpBind();
	afx_msg void OnBtnUdpSendMsg();
	afx_msg void OnBtnUdpClose();
	afx_msg void OnBtnHttpServer();
	afx_msg void OnBtnStopHttpServer();
	afx_msg void OnBtnWebsocketServer();
	afx_msg void OnBtnWebsocketServerStop();
	afx_msg void OnBtnWebsocketConnect();
	afx_msg void OnBtnWebsocketDisconnectServer();
};
