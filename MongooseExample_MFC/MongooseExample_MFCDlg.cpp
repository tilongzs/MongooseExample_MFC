#include "pch.h"
#include "framework.h"
#include "MongooseExample_MFC.h"
#include "MongooseExample_MFCDlg.h"
#include "afxdialogex.h"
#include "Common/Common.h"
#include <afxsock.h>

#include <sys/types.h>  
#include <errno.h>  
#include <corecrt_io.h>
#include <thread>
#include <chrono>
#include <fcntl.h>
#include <sys/stat.h>

// vcpkg管理
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <wincrypt.h>
/*******************************/

using namespace std;
using namespace chrono;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define WMSG_FUNCTION		WM_USER + 1
#define DEFAULT_SOCKET_PORT 23300
#define SINGLE_PACKAGE_SIZE 1024 * 64 // 默认16384
#define SINGLE_UDP_PACKAGE_SIZE 65507 // 单个UDP包的最大大小（理论值：65507字节）
#define URL_MAX 4096

#define HTTP_MAX_HEAD_SIZE 1024 * 4
static const INT64 HTTP_MAX_BODY_SIZE = (INT64)1024 * 1024 * 1024 * 2 - 1024; // 不要超过2GB

static CString GenerateIPPortString(const mg_addr& addr)
{
	string remoteIP;
	ConvertIPNet2Local(addr.ip, remoteIP);
	CString tmpStr;
	tmpStr.Format(L"%s:%d", S2Unicode(remoteIP.c_str()).c_str(), mg_ntohs(addr.port));
	return tmpStr;
}

struct EventData
{
public:
	EventData(CMongooseExample_MFCDlg* mainDlg) :dlg(mainDlg) {}
	~EventData()
	{
		// 		if (bev)
		// 		{
		// 			bufferevent_free(bev);
		// 		}

// 		if (ssl_ctx)
// 		{
// 			SSL_CTX_free(ssl_ctx);
// 		}
	}

	CMongooseExample_MFCDlg* dlg = nullptr;
	mg_connection* conn = nullptr;
};

// struct HttpData
// {
// public:
// 	~HttpData()
// 	{
// 		Free();
// 	}
// 
// 	void Free()
// 	{
// 		_mtx.lock();
// 		if (evConn)
// 		{
// 			evhttp_connection_free(evConn);
// 			evConn = nullptr;
// 		}
// 
// 		if (evURI)
// 		{
// 			evhttp_uri_free(evURI);
// 			evURI = nullptr;
// 		}
// 
// 		if (ssl_ctx)
// 		{
// 			SSL_CTX_free(ssl_ctx);
// 			ssl_ctx = nullptr;
// 		}
// 
// 		if (req)
// 		{
// 			evhttp_request_free(req);
// 			req = nullptr;
// 		}
// 		_mtx.unlock();
// 	}
// 
// 	CMongooseExample_MFCDlg* dlg = nullptr;
// 	evhttp_connection* evConn = nullptr;
// 	evhttp_uri* evURI = nullptr;
// 	evhttp_request* req = nullptr;
// 
// 	bufferevent* bev = nullptr;
// 	ssl_ctx_st* ssl_ctx = nullptr;
// 	ssl_st* ssl = nullptr;
// 
// private:
// 	mutex _mtx;
// };

CMongooseExample_MFCDlg::CMongooseExample_MFCDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MongooseExample_MFC_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMongooseExample_MFCDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_IPADDRESS1, _ipRemote);
	DDX_Control(pDX, IDC_EDIT_MSG, _editRecv);
	DDX_Control(pDX, IDC_EDIT_PORT, _editPort);
	DDX_Control(pDX, IDC_EDIT_PORT_REMOTE, _editRemotePort);
	DDX_Control(pDX, IDC_CHECK_SSL, _btnUseSSL);
	DDX_Control(pDX, IDC_BUTTON_HTTP_SERVER, _btnHTTPServer);
	DDX_Control(pDX, IDC_BUTTON_HTTP_SERVER_STOP, _btnStopHttpServer);
}

BEGIN_MESSAGE_MAP(CMongooseExample_MFCDlg, CDialogEx)
	ON_WM_QUERYDRAGICON()
	ON_MESSAGE(WMSG_FUNCTION, &CMongooseExample_MFCDlg::OnFunction)
	ON_BN_CLICKED(IDC_BUTTON_DISCONN_CLIENT, &CMongooseExample_MFCDlg::OnBtnDisconnClient)
	ON_BN_CLICKED(IDC_BUTTON_LISTEN, &CMongooseExample_MFCDlg::OnBtnListen)
	ON_BN_CLICKED(IDC_BUTTON_CREATETIMER, &CMongooseExample_MFCDlg::OnBtnCreatetimer)
	ON_BN_CLICKED(IDC_BUTTON_STOP_LISTEN, &CMongooseExample_MFCDlg::OnBtnStopListen)
	ON_BN_CLICKED(IDC_BUTTON_CONNECT, &CMongooseExample_MFCDlg::OnBtnConnect)
	ON_BN_CLICKED(IDC_BUTTON_DISCONNECT_SERVER, &CMongooseExample_MFCDlg::OnBtnDisconnectServer)
	ON_BN_CLICKED(IDC_BUTTON_SEND_MSG, &CMongooseExample_MFCDlg::OnBtnSendMsg)
	ON_BN_CLICKED(IDC_BUTTON_UDP_BIND, &CMongooseExample_MFCDlg::OnBtnUdpBind)
	ON_BN_CLICKED(IDC_BUTTON_UDP_SEND_MSG, &CMongooseExample_MFCDlg::OnBtnUdpSendMsg)
	ON_BN_CLICKED(IDC_BUTTON_UDP_CLOSE, &CMongooseExample_MFCDlg::OnBtnUdpClose)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_SERVER, &CMongooseExample_MFCDlg::OnBtnHttpServer)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_SERVER_STOP, &CMongooseExample_MFCDlg::OnBtnStopHttpServer)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_GET, &CMongooseExample_MFCDlg::OnBtnHttpGet)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_POST_FILE, &CMongooseExample_MFCDlg::OnBtnHttpPostFile)
END_MESSAGE_MAP()

BOOL CMongooseExample_MFCDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE);

	_editPort.SetWindowText(L"23300");
	_ipRemote.SetAddress(127, 0, 0, 1);
	_editRemotePort.SetWindowText(L"23300");

	_btnStopHttpServer.EnableWindow(FALSE);

	AfxSocketInit();

	// 初始化公用Mongoose管理器
	mg_mgr_init(&_mgr);
	thread([&]
		{
			while (true)
			{
				mg_mgr_poll(&_mgr, 1);
			}
		}).detach();

	AppendMsg(L"启动 Mongoose is not thread-safe");
	return TRUE;
}

HCURSOR CMongooseExample_MFCDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CMongooseExample_MFCDlg::AppendMsg(const WCHAR* msg)
{
	WCHAR* tmpMsg = new WCHAR[wcslen(msg) + 1];
	memset(tmpMsg, 0, sizeof(WCHAR) * (wcslen(msg) + 1));
	wsprintf(tmpMsg, msg);

	TheadFunc* pFunc = new TheadFunc;
	pFunc->Func = ([=]()
	{
		if (_editRecv.GetLineCount() > 100)
		{
			_editRecv.Clear();
		}

		CString curMsg;
		_editRecv.GetWindowTextW(curMsg);
		curMsg += "\r\n";

		CString strTime;
		SYSTEMTIME   tSysTime;
		GetLocalTime(&tSysTime);
		strTime.Format(L"%02ld:%02ld:%02ld.%03ld ",
			tSysTime.wHour, tSysTime.wMinute, tSysTime.wSecond, tSysTime.wMilliseconds);

		curMsg += strTime;
		curMsg += tmpMsg;
		_editRecv.SetWindowTextW(curMsg);
		_editRecv.LineScroll(_editRecv.GetLineCount());

		delete[] tmpMsg;
	});

	PostMessage(WMSG_FUNCTION, (WPARAM)pFunc);
}

bool CMongooseExample_MFCDlg::IsUseSSL()
{
	return _btnUseSSL.GetCheck();
}

void CMongooseExample_MFCDlg::OnTCPAccept(shared_ptr<EventData> eventData)
{
	_currentEventData = eventData;
}

void CMongooseExample_MFCDlg::OnDisconnectClient(mg_connection* conn)
{
	if (_currentEventData && _currentEventData->conn == conn)
	{
		_currentEventData = nullptr;
	}
}

void CMongooseExample_MFCDlg::OnDisconnectServer()
{
	_isNeedDeleteMgr = true;
}

LRESULT CMongooseExample_MFCDlg::OnFunction(WPARAM wParam, LPARAM lParam)
{
	TheadFunc* pFunc = (TheadFunc*)wParam;
	pFunc->Func();
	delete pFunc;

	return TRUE;
}

void timer_fn(void* arg)
{
	CMongooseExample_MFCDlg* dlg = (CMongooseExample_MFCDlg*)arg;
	dlg->AppendMsg(L"定时器");
}

void CMongooseExample_MFCDlg::OnBtnCreatetimer()
{
	/*mg_timer* timer = */mg_timer_add(&_mgr, 2000, MG_TIMER_ONCE/*一次性*/, timer_fn, this);
}

void CMongooseExample_MFCDlg::OnBtnDisconnClient()
{
	if (_currentEventData)
	{
		AppendMsg(L"手动断开与当前客户端连接");
		_currentEventData->conn->is_draining = true;
	}
}

void OnTCPServerEvent(mg_connection* conn, int ev, void* ev_data, void* fn_data)
{
	EventData* listenEventData = (EventData*)fn_data;
	CString tmpStr;

	switch (ev)
	{
	case MG_EV_ERROR:
	{
		CString tmpStr;
		tmpStr.Format(L"TCP服务端发生错误 remote:%s local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_POLL:
		break;
	case MG_EV_OPEN:
	{
		CString tmpStr;
		tmpStr.Format(L"TCP服务端连接已准备 local:%s", GenerateIPPortString(conn->loc));
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_RESOLVE:
	{
		CString tmpStr;
		tmpStr.Format(L"MG_EV_RESOLVE remote:%s local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_ACCEPT:
	{
		CString tmpStr;
		tmpStr.Format(L"新客户端连接 remote:%s", GenerateIPPortString(conn->rem));
		listenEventData->dlg->AppendMsg(tmpStr);

		// 修改socket属性
		const int bufLen = SINGLE_PACKAGE_SIZE;
		if (setsockopt(SOCKET(conn->fd), SOL_SOCKET, SO_RCVBUF, (const char*)&bufLen, sizeof(int)) < 0)
		{
			return;
		}
		if (setsockopt(SOCKET(conn->fd), SOL_SOCKET, SO_SNDBUF, (const char*)&bufLen, sizeof(int)) < 0)
		{
			return;
		}

		linger optLinger;
		optLinger.l_onoff = 1;
		optLinger.l_linger = 0;
		if (setsockopt(SOCKET(conn->fd), SOL_SOCKET, SO_LINGER, (const char*)&optLinger, sizeof(linger)) != 0)
		{
			return;
		}

		if (listenEventData->dlg->IsUseSSL())
		{
			CString exeDir = GetModuleDir();
			string serverCrtPath = UnicodeToUTF8(CombinePath(exeDir, L"../3rd/OpenSSL/server.crt"));
			string serverKeyPath = UnicodeToUTF8(CombinePath(exeDir, L"../3rd/OpenSSL/server.key"));
			mg_tls_opts tlsOpts;
			memset(&tlsOpts, 0, sizeof(mg_tls_opts));
			tlsOpts.cert = serverCrtPath.c_str();
			tlsOpts.certkey = serverKeyPath.c_str();
			mg_tls_init(conn, &tlsOpts);
		}

		shared_ptr<EventData> eventData = make_shared<EventData>(listenEventData->dlg);
		eventData->conn = conn;
		listenEventData->dlg->OnTCPAccept(eventData);
	}
	break;
	case MG_EV_CLOSE:
	{
		CString tmpStr;
		tmpStr.Format(L"与客户端%s的连接断开", GenerateIPPortString(conn->rem));
		listenEventData->dlg->AppendMsg(tmpStr);

		listenEventData->dlg->OnDisconnectClient(conn);
	}
	break;
	case MG_EV_READ:
	{
		mg_str* recvData = (mg_str*)ev_data;
		mg_iobuf& r = conn->recv;

		CString tmpStr;
		tmpStr.Format(L"收到客户端%s发来的 %u字节", GenerateIPPortString(conn->rem), r.len);
		listenEventData->dlg->AppendMsg(tmpStr);

		// 告诉Mongoose已经处理了数据
		r.len = 0;
	}
	break;
	case MG_EV_WRITE:
	{
		long* bytes_written = (long*)ev_data;

		CString tmpStr;
		tmpStr.Format(L"已发送给客户端%s %u字节", GenerateIPPortString(conn->rem), *bytes_written);
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	default:
		listenEventData->dlg->AppendMsg(L"OnTCPServerEvent default");
		break;
	}
}

void CMongooseExample_MFCDlg::OnBtnListen()
{
	_isNeedDeleteMgr = false;

	mg_mgr* mgr = new mg_mgr;
	mg_mgr_init(mgr);
	thread([&, mgr]
	{
		while (!_isNeedDeleteMgr)
		{
			mg_mgr_poll(mgr, 1);
		}

		mg_mgr_free(mgr);
		_listenEventData = nullptr;
		AppendMsg(L"TCP服务端事件循环结束");
	}).detach();

	CString tmpStr;
	_editPort.GetWindowText(tmpStr);
	const int port = _wtoi(tmpStr);
	CStringA url;
	url.Format("tcp://0.0.0.0:%d", port);

	CString strLog;
	strLog.Format(L"TCP开始监听：%s", S2Unicode(url).c_str());
	AppendMsg(strLog);
	_listenEventData = make_shared<EventData>(this);

	_listenEventData->conn = mg_listen(mgr, url, OnTCPServerEvent, _listenEventData.get());
	if (!_listenEventData->conn)
	{
		AppendMsg(L"TCP开始监听失败");
		_isNeedDeleteMgr = true;
	}
}

void CMongooseExample_MFCDlg::OnBtnStopListen()
{
	if (_listenEventData)
	{
		AppendMsg(L"服务端手动停止监听");
		_listenEventData->conn->is_draining = true;
	}

	// 关闭事件循环
	_isNeedDeleteMgr = true;
}

void OnTCPClientEvent(mg_connection* conn, int ev, void* ev_data, void* fn_data)
{
	EventData* eventData = (EventData*)fn_data;
	CString tmpStr;

	switch (ev)
	{
	case MG_EV_ERROR:
	{
		CString tmpStr;
		tmpStr.Format(L"TCP客户端发生错误 remote:%s local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		eventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_POLL:
		break;
	case MG_EV_OPEN:
	{
		CString tmpStr;
		tmpStr.Format(L"TCP客户端初始化完成 local:%s", GenerateIPPortString(conn->loc));
		eventData->dlg->AppendMsg(tmpStr);
		break;
	}
	break;
	case MG_EV_CONNECT:
	{
		CString tmpStr;
		tmpStr.Format(L"与服务端remote:%s连接成功 local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		eventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_RESOLVE:
	{
		CString tmpStr;
		tmpStr.Format(L"MG_EV_RESOLVE remote:%s local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		eventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_CLOSE:
	{
		CString tmpStr;
		tmpStr.Format(L"与服务端remote:%s连接断开 local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		eventData->dlg->AppendMsg(tmpStr);

		eventData->dlg->OnDisconnectServer();
	}
	break;
	case MG_EV_READ:
	{
		mg_str* recvData = (mg_str*)ev_data;
		mg_iobuf& r = conn->recv;

		CString tmpStr;
		tmpStr.Format(L"收到服务端%s发来的 %u字节", GenerateIPPortString(conn->rem), r.len);
		eventData->dlg->AppendMsg(tmpStr);

		// 告诉Mongoose已经处理了数据
		r.len = 0;
	}
	break;
	case MG_EV_WRITE:
	{
		long* bytes_written = (long*)ev_data;

		CString tmpStr;
		tmpStr.Format(L"已发送给服务端%s %u字节", GenerateIPPortString(conn->rem), *bytes_written);
		eventData->dlg->AppendMsg(tmpStr);
	}
	break;
	default:
		eventData->dlg->AppendMsg(L"OnTCPEvent default");
		break;
	}
}

void CMongooseExample_MFCDlg::OnBtnConnect()
{
	_isNeedDeleteMgr = false;

	// 使用指定的本地IP、端口
	CString tmpStr;
	DWORD dwRemoteIP;
	_ipRemote.GetAddress(dwRemoteIP);
	string remoteIP;
	ConvertIPLocal2Local(dwRemoteIP, remoteIP);

	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	mg_mgr* mgr = new mg_mgr;
	mg_mgr_init(mgr);
	thread([&, mgr]
	{
		while (!_isNeedDeleteMgr)
		{
			mg_mgr_poll(mgr, 1);
		}

		mg_mgr_free(mgr);
		AppendMsg(L"TCP客户端事件循环结束");
	}).detach();

	CStringA url;
	url.Format("tcp://%s:%d", remoteIP.c_str(), remotePort);
	CString strLog;
	strLog.Format(L"开始连接服务端：%s", S2Unicode(url).c_str());
	AppendMsg(strLog);

	_currentEventData = make_shared<EventData>(this);
#ifdef _USE_RANDOM_LOCALPORT
	// 使用任意本地端口连接服务端
	_currentEventData->conn = mg_connect(mgr, url, OnTCPClientEvent, _currentEventData.get());
	if (nullptr == _currentEventData->conn)
	{
		_isNeedDeleteMgr = true;
		AppendMsg(L"mg_connect失败");
		return;
	}
#else
	// 使用指定本地端口连接服务端
	_editPort.GetWindowText(tmpStr);
	const int localPort = _wtoi(tmpStr);
	SOCKADDR_IN localAddr;
	ConvertIPPort("0.0.0.0", localPort, localAddr);

	SOCKET sockfd = socket(AF_INET, SOCK_STREAM, 0);
	// 修改socket属性
	const int bufLen = SINGLE_PACKAGE_SIZE;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char*)&bufLen, sizeof(int)) < 0)
	{
		return;
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char*)&bufLen, sizeof(int)) < 0)
	{
		return;
	}

	// closesocket时强行关闭连接，尚未发出的所有数据都会丢失；用于避免TIME_WAIT。
	linger optLinger;
	optLinger.l_onoff = 1;
	optLinger.l_linger = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (const char*)&optLinger, sizeof(linger)) != 0)
	{
		_isNeedDeleteMgr = true;
		::closesocket(sockfd);
		AppendMsg(L"TCP客户端setsockopt SO_LINGER失败");
		return;
	}

	if (0 != ::bind(sockfd, (sockaddr*)&localAddr, sizeof(sockaddr)))
	{
		_isNeedDeleteMgr = true;
		::closesocket(sockfd);
		AppendMsg(L"绑定本地端口失败");
		return;
	}

	_currentEventData->conn = mg_wrapfd(mgr, sockfd, OnTCPClientEvent, _currentEventData.get());
	if (nullptr == _currentEventData->conn)
	{
		_isNeedDeleteMgr = true;
		::closesocket(sockfd);
		AppendMsg(L"mg_wrapfd失败");
		return;
	}

	// 开始连接
	mg_resolve(_currentEventData->conn, url);
#endif

	if (IsUseSSL())
	{
		mg_tls_opts tlsOpts;
		memset(&tlsOpts, 0, sizeof(mg_tls_opts));
		mg_tls_init(_currentEventData->conn, &tlsOpts);
	}
}

void CMongooseExample_MFCDlg::OnBtnDisconnectServer()
{
	if (_currentEventData && _currentEventData->conn)
	{
		AppendMsg(L"客户端手动断开连接");

		_currentEventData->conn->is_draining = true;
	}

	// 关闭事件循环
	_isNeedDeleteMgr = true;
}

void CMongooseExample_MFCDlg::OnBtnSendMsg()
{
	thread([&] 
	{
		if (_currentEventData)
		{
			// 		char* msg = new char[]("hello Mongoose");
			// 		int len = strlen(msg);

			const int len = 1024 * 10;
			char* msg = new char[len] {0};

			if (mg_send(_currentEventData->conn, msg, len))
			{
				CString tmpStr;
				tmpStr.Format(L"发送%u字节数据", len);
				AppendMsg(tmpStr);
			}
			else
			{
				AppendMsg(L"发送数据失败");
			}

			delete[] msg;
		}
	}).detach();
}

// static void OnUDPRead(evutil_socket_t sockfd, short events, void* param)
// {
// 	EventData* eventData = (EventData*)param;
// 
// 	if (events & EV_READ)
// 	{
// 		struct sockaddr_in addr;
// 		socklen_t addLen = sizeof(addr);
// 		char* buffer = new char[SINGLE_UDP_PACKAGE_SIZE] {0};
// 
// 		int recvLen = recvfrom(sockfd, buffer, SINGLE_UDP_PACKAGE_SIZE, 0, (sockaddr*)&addr, &addLen);
// 		if (recvLen == -1)
// 		{
// 			eventData->dlg->AppendMsg(L"recvfrom 失败");
// 		}
// 		else
// 		{
// 			string remoteIP;
// 			int remotePort;
// 			ConvertIPPort(addr, remoteIP, remotePort);
// 
// 			CString tmpStr;
// 			tmpStr.Format(L"threadID:%d 收到来自%s:%d %u字节", this_thread::get_id(), S2Unicode(remoteIP).c_str(), remotePort, recvLen);
// 			eventData->dlg->AppendMsg(tmpStr);
// 		}
// 
// 		delete[] buffer;
// 	}
// }

void OnUDPEvent(mg_connection* conn, int ev, void* ev_data, void* fn_data)
{
	EventData* listenEventData = (EventData*)fn_data;
	CString tmpStr;

	switch (ev)
	{
	case MG_EV_ERROR:
	{
		CString tmpStr;
		tmpStr.Format(L"UDP发生错误 remote:%s local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_OPEN:
	{
		CString tmpStr;
		tmpStr.Format(L"UDP初始化完成 local:%s", GenerateIPPortString(conn->loc));
		listenEventData->dlg->AppendMsg(tmpStr);
		break;
	}
	break;
	case MG_EV_POLL:
		break;
	case MG_EV_RESOLVE:
	{
		CString tmpStr;
		tmpStr.Format(L"MG_EV_RESOLVE remote:%s local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_CLOSE:
	{
		listenEventData->dlg->AppendMsg(L"UDP监听停止");
		listenEventData->dlg->OnDisconnectServer();
	}
	break;
	case MG_EV_READ:
	{
		mg_str* recvData = (mg_str*)ev_data;
		mg_iobuf& r = conn->recv;

		CString tmpStr;
		tmpStr.Format(L"收到客户端%s发来的 %u字节", GenerateIPPortString(conn->rem), r.len);
		listenEventData->dlg->AppendMsg(tmpStr);

		// 告诉Mongoose已经处理了数据
		r.len = 0;
	}
	break;
	case MG_EV_WRITE:
	{
		long* bytes_written = (long*)ev_data;

		CString tmpStr;
		tmpStr.Format(L"已发送给客户端%s %u字节", GenerateIPPortString(conn->rem), *bytes_written);
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	default:
		listenEventData->dlg->AppendMsg(L"OnUDPEvent default");
		break;
	}
}

void CMongooseExample_MFCDlg::OnBtnUdpBind()
{
	_isNeedDeleteMgr = false;

	mg_mgr* mgr = new mg_mgr;
	mg_mgr_init(mgr);
	thread([&, mgr]
	{
		while (!_isNeedDeleteMgr)
		{
			mg_mgr_poll(mgr, 1000);
		}

		mg_mgr_free(mgr);
		_listenEventData = nullptr;
		AppendMsg(L"UDP监听事件循环结束");
	}).detach();

	CString tmpStr;
	_editPort.GetWindowText(tmpStr);
	const int port = _wtoi(tmpStr);
	CStringA url;
	url.Format("udp://0.0.0.0:%d", port);

	CString strLog;
	strLog.Format(L"UDP开始监听：%s", S2Unicode(url).c_str());
	AppendMsg(strLog);

	_listenEventData = make_shared<EventData>(this);
	_listenEventData->conn = mg_listen(mgr, url, OnUDPEvent, _listenEventData.get());
	if (!_listenEventData->conn)
	{
		AppendMsg(L"UDP开始监听失败");
		_isNeedDeleteMgr = true;
	}
}

void CMongooseExample_MFCDlg::OnBtnUdpSendMsg()
{
	DWORD dwRemoteIP;
	_ipRemote.GetAddress(dwRemoteIP);

	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);
	sockaddr_in remoteAddr = { 0 };
	ConvertIPPort(dwRemoteIP, remotePort, remoteAddr);

	if (_listenEventData)
	{
		const int len = SINGLE_UDP_PACKAGE_SIZE;
		char* msg = new char[len] {0};
		int sendLen = sendto(SOCKET(_listenEventData->conn->fd), msg, len, 0, (sockaddr*)&remoteAddr, sizeof(sockaddr_in));
		if (sendLen == -1)
		{
			AppendMsg(L"UDP发送失败");
		}

		delete[] msg;
	}
}

void CMongooseExample_MFCDlg::OnBtnUdpClose()
{
	if (_listenEventData)
	{
		AppendMsg(L"服务端手动停止监听");
		_listenEventData->conn->is_draining = true;
	}

	// 关闭事件循环
	_isNeedDeleteMgr = true;
}

static void OnHTTPServerEvent(struct mg_connection* conn, int ev, void* ev_data, void* fn_data) 
{
	EventData* listenEventData = (EventData*)fn_data;
	CString tmpStr;

	switch (ev)
	{
	case MG_EV_ERROR:
	case MG_EV_OPEN:
	case MG_EV_POLL:
		break;
	case MG_EV_ACCEPT:
	{
		if (listenEventData->dlg->IsUseSSL())
		{
			CString exeDir = GetModuleDir();
			string serverCrtPath = UnicodeToUTF8(CombinePath(exeDir, L"../3rd/OpenSSL/server.crt"));
			string serverKeyPath = UnicodeToUTF8(CombinePath(exeDir, L"../3rd/OpenSSL/server.key"));
			mg_tls_opts tlsOpts;
			memset(&tlsOpts, 0, sizeof(mg_tls_opts));
			tlsOpts.cert = serverCrtPath.c_str();
			tlsOpts.certkey = serverKeyPath.c_str();
			mg_tls_init(conn, &tlsOpts);
		}
	}
	break;
	case MG_EV_READ:
	case MG_EV_WRITE:
	case MG_EV_CLOSE:
		break;
	case MG_EV_HTTP_MSG:
	{
		mg_http_message* hm = (mg_http_message*)ev_data;
		if (mg_http_match_uri(hm, "/api/getA"))
		{
			mg_http_reply(conn, 200, "", "{\"result\": \"%.*s\"}\n", (int)hm->uri.len, hm->uri.ptr);
		} 
		else if (mg_http_match_uri(hm, "/api/postA"))
		{
			mg_http_reply(conn, 200, "", "{\"result\": \"%.*s\"}\n", (int)hm->uri.len, hm->uri.ptr);
		}
		else
		{
			// 文件目录服务
			struct mg_http_serve_opts opts;
			memset(&opts, 0, sizeof(opts));
			opts.root_dir = "D:/SoftwareDev";
			mg_http_serve_dir(conn, hm, &opts);
		}

		tmpStr.Format(L"收到MG_EV_HTTP_MSG uri:%s", CString(hm->uri.ptr));
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_HTTP_CHUNK:
	{
		mg_http_message* hm = (mg_http_message*)ev_data;

		static int chunkCount = 0;
		chunkCount += hm->chunk.len;

		if (0 == hm->chunk.len)
		{
			// 数据分块接收完成，开始回复
			if (mg_http_match_uri(hm, "/api/postA"))
			{
				mg_http_reply(conn, 200, "", "{\"result\": \"%.*s\"}\n", (int)hm->uri.len, hm->uri.ptr);
			}

			tmpStr.Format(L"收到MG_EV_HTTP_CHUNK数据分块接收完成 chunkCount:%d", chunkCount);
			listenEventData->dlg->AppendMsg(tmpStr);

			// 重置计数
			chunkCount = 0;
		}
		
// 		tmpStr.Format(L"收到MG_EV_HTTP_CHUNK chunkLen:%d chunkCount:%d", hm->chunk.len, chunkCount);
// 		listenEventData->dlg->AppendMsg(tmpStr);

		mg_http_delete_chunk(conn, hm);
	}
	break;
	default:
	{
		tmpStr.Format(L"OnHTTPServerEvent unhandle ev:%d", ev);
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	}
}

void CMongooseExample_MFCDlg::OnBtnHttpServer()
{
	_isNeedDeleteMgr = false;

	mg_mgr* mgr = new mg_mgr;
	mg_mgr_init(mgr);
	thread([&, mgr]
	{
		while (!_isNeedDeleteMgr)
		{
			mg_mgr_poll(mgr, 1);
		}

		mg_mgr_free(mgr);
		_listenEventData = nullptr;
		AppendMsg(L"HTTP服务端事件循环结束");
	}).detach();

	CString tmpStr;
	_editPort.GetWindowText(tmpStr);
	const int port = _wtoi(tmpStr);
	CStringA url;
	if (IsUseSSL())
	{
		url.Format("https://0.0.0.0:%d", port);
	}
	else
	{
		url.Format("http://0.0.0.0:%d", port);
	}

	_listenEventData = make_shared<EventData>(this);
	_listenEventData->conn = mg_http_listen(mgr, url, OnHTTPServerEvent, _listenEventData.get());
	if (!_listenEventData->conn) 
	{
		AppendMsg(L"HTTP开始监听失败");
		_isNeedDeleteMgr = true;
		return;
	}

	AppendMsg(L"HTTP开始监听");
	_btnHTTPServer.EnableWindow(FALSE);
	_btnStopHttpServer.EnableWindow(TRUE);
}

void CMongooseExample_MFCDlg::OnBtnStopHttpServer()
{
	if (_listenEventData)
	{
		_listenEventData->conn->is_draining = true;
		AppendMsg(L"HTTP 服务端停止");
		_btnHTTPServer.EnableWindow(TRUE);
		_btnStopHttpServer.EnableWindow(FALSE);
	}

	// 关闭事件循环
	_isNeedDeleteMgr = true;
}

void CMongooseExample_MFCDlg::OnBtnHttpGet()
{
	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	CString strURI;
	strURI.Format(L"http://127.0.0.1:%d/api/getA?q=test&s=some+thing", remotePort);
	string utf8URI = UnicodeToUTF8(strURI);
	const char* uri = utf8URI.c_str();

	// 	evthread_use_windows_threads();
	// 	event_base* eventBase = event_base_new();
	// 
	// 	HttpData* httpData = new HttpData;
	// 	httpData->dlg = this;
	// 
	// 	httpData->evURI = evhttp_uri_parse(uri);
	// 	const char* host = evhttp_uri_get_host(httpData->evURI);
	// 	int port = evhttp_uri_get_port(httpData->evURI);
	// 	httpData->evConn = evhttp_connection_base_new(eventBase, NULL, host, port);
	// 
	// 	evhttp_request* req = evhttp_request_new(OnHttpResponseGetA, httpData);
	// 
	// 	evhttp_make_request(httpData->evConn, req, EVHTTP_REQ_GET, "/api/getA?q=test&s=some+thing");
	// 	
	// 	thread([&, eventBase, httpData]
	// 	{
	// 		event_base_dispatch(eventBase); // 阻塞
	// 		AppendMsg(L"客户端HttpGet event_base_dispatch线程 结束");
	// 
	// 		// 先断开连接，后释放eventBase
	// 		delete httpData;
	// 		event_base_free(eventBase);
	// 	}).detach();
}

// static void OnHttpResponsePostFileA(evhttp_request* req, void* arg)
// {
// 	HttpData* httpData = (HttpData*)arg;
// 	if (req)
// 	{
// 		// 获取数据长度
// 		size_t len = evbuffer_get_length(req->input_buffer);
// 		if (len > 0)
// 		{
// 			// 获取数据指针
// 			unsigned char* data = evbuffer_pullup(req->input_buffer, len);
// 
// 			// 处理数据...
// 
// 			// 清空数据
// 			evbuffer_drain(req->input_buffer, len);
// 		}
// 		evhttp_request_free(req);
// 
// 		CString strMsg;
// 		strMsg.Format(L"收到PostFileA接口回复%u字节数据", len);
// 		httpData->dlg->AppendMsg(strMsg);
// 	}
// 	else
// 	{
// 		httpData->dlg->AppendMsg(L"PostFileA失败");
// 	}
// 
// 	// 主动断开与服务器连接
// 	//httpData->Free();
// }

void CMongooseExample_MFCDlg::OnBtnHttpPostFile()
{
	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	CFileDialog dlg(TRUE, NULL, NULL, OFN_FILEMUSTEXIST,
		_T("All Files (*.*)|*.*||"),
		NULL);
	if (dlg.DoModal() != IDOK)
	{
		return;
	}

	// 加载文件
	/*
	* _wsopen_s说明
	https://docs.microsoft.com/zh-cn/previous-versions/w64k0ytk(v=vs.110)?redirectedfrom=MSDN
	*/
	int readFile = NULL;
	int ret = _wsopen_s(&readFile, dlg.GetPathName(), _O_RDONLY | _O_BINARY, _SH_DENYWR, _S_IREAD); // 使用宽字节接口解决中文问题
	if (0 != ret)
	{
		AppendMsg(L"读取文件失败");
		return;
	}

	struct _stat64 st;
	_wstat64(dlg.GetPathName(), &st); // 获取文件信息
	if (st.st_size > HTTP_MAX_BODY_SIZE)
	{
		AppendMsg(L"文件体积过大");
		return;
	}

	CString strURI;
	strURI.Format(L"http://127.0.0.1:%d/api/postFileA?q=test&s=some+thing", remotePort);
	string utf8URI = UnicodeToUTF8(strURI);
	const char* uri = utf8URI.c_str();

	// 	evthread_use_windows_threads();
	// 	event_base* eventBase = event_base_new();
	// 
	// 	HttpData* httpData = new HttpData;
	// 	httpData->dlg = this;
	// 
	// 	httpData->evURI = evhttp_uri_parse(uri);
	// 	const char* host = evhttp_uri_get_host(httpData->evURI);
	// 	int port = evhttp_uri_get_port(httpData->evURI);
	// 
	// 	if (IsUseSSL())
	// 	{
	// 		// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
	// 		httpData->ssl_ctx = SSL_CTX_new(TLS_client_method());
	// 		httpData->ssl = SSL_new(httpData->ssl_ctx);
	// 		httpData->bev = bufferevent_openssl_socket_new(eventBase, -1, httpData->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	// 		if (httpData->bev)
	// 		{
	// 			bufferevent_openssl_set_allow_dirty_shutdown(httpData->bev, 1);
	// 		}
	// 	}
	// 	else
	// 	{
	// 		httpData->bev = bufferevent_socket_new(eventBase, -1, BEV_OPT_CLOSE_ON_FREE);
	// 	}
	// 	if (httpData->bev == NULL)
	// 	{
	// 		AppendMsg(L"bev创建失败");
	// 		delete httpData;
	// 		return;
	// 	}
	// 
	// 	httpData->evConn = evhttp_connection_base_bufferevent_new(eventBase, NULL, httpData->bev, host, port);
	// 	if (httpData->evConn == NULL)
	// 	{
	// 		AppendMsg(L"evhttp_connection_base_bufferevent_new失败");
	// 		delete httpData;
	// 		return;
	// 	}
	// 
	// 	evhttp_connection_set_max_headers_size(httpData->evConn, HTTP_MAX_HEAD_SIZE);
	// 	evhttp_connection_set_max_body_size(httpData->evConn, HTTP_MAX_BODY_SIZE);
	// 	//evhttp_connection_set_timeout(httpData->evConn, 30);// 可以不设置超时时间；设置超时时间，文件越大，需要的时间越长(s)
	// 
	// 	evhttp_request* req = evhttp_request_new(OnHttpResponsePostFileA, httpData);
	// 
	// 	// 标准Header
	// 	evhttp_add_header(req->output_headers, "Connection", "keep-alive");
	// 	evhttp_add_header(req->output_headers, "Host", "localhost");
	// 
	// 	// 自定义Header
	// 	const size_t fileSize = st.st_size; // 单次最大2GB（1024 * 1024 * 1024 - 1024）
	// 	string strFileName = UnicodeToUTF8(dlg.GetFileName()); // 文件名使用UTF-8存储
	// 	evhttp_add_header(req->output_headers, "FileName", strFileName.c_str());
	// 	evhttp_add_header(req->output_headers, "FileSize", Int2Str(fileSize).c_str());
	// 
	// 	// 文件数据
	// 	ret = evbuffer_add_file(req->output_buffer, readFile, 0, fileSize);
	// 	if (0 != ret)
	// 	{
	// 		AppendMsg(L"evbuffer_add_file失败");
	// 		event_base_free(eventBase);
	// 		return;
	// 	}
	// 
	// 	evhttp_make_request(httpData->evConn, req, EVHTTP_REQ_POST, "/api/postFileA?q=test&s=some+thing");
	// 
	// 	thread([&, eventBase, httpData]
	// 		{
	// 			event_base_dispatch(eventBase); // 阻塞
	// 			AppendMsg(L"客户端HttpPost event_base_dispatch线程 结束");
	// 
	// 			// 先断开连接，后释放eventBase
	// 			delete httpData;
	// 			event_base_free(eventBase);
	// 		}).detach();
}
