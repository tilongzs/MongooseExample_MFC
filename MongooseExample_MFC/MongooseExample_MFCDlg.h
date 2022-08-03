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

	mg_mgr	_mgr;	// 公用Mongoose管理器

	// TCP/UDP
	shared_ptr<EventData> _listenEventData = nullptr;
	shared_ptr<EventData> _currentEventData = nullptr;
	bool			_isNeedDeleteMgr = false;

	// HTTP
	// 	evhttp* _httpServer = nullptr;
	// 	evhttp_bound_socket* _httpSocket;

public:
	void AppendMsg(const WCHAR* msg);
	bool IsUseSSL();
	void OnTCPAccept(shared_ptr<EventData> eventData); // 与服务端建立连接
	void OnDisconnectClient(mg_connection* conn);
	void OnDisconnectServer();
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
public:
	afx_msg void OnBtnHttpGet();
	afx_msg void OnBtnHttpPost();
	afx_msg void OnBtnHttpPut();
	afx_msg void OnBtnHttpPostFile();
	afx_msg void OnBtnHttpDel();
};
