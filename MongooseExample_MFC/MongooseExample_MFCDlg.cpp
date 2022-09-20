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
	ON_BN_CLICKED(IDC_BUTTON_WS_SERVER, &CMongooseExample_MFCDlg::OnBtnWebsocketServer)
	ON_BN_CLICKED(IDC_BUTTON_WS_SERVER_STOP, &CMongooseExample_MFCDlg::OnBtnWebsocketServerStop)
	ON_BN_CLICKED(IDC_BUTTON_WS_CONNECT, &CMongooseExample_MFCDlg::OnBtnWebsocketConnect)
	ON_BN_CLICKED(IDC_BUTTON_WS_DISCONNECT_SERVER, &CMongooseExample_MFCDlg::OnBtnWebsocketDisconnectServer)
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

	AppendMsg(L"启动 Mongoose is not thread-safe");
	AppendMsg(L"#define MG_IO_SIZE (1024 * 64) // 修改默认值");
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

void CMongooseExample_MFCDlg::OnSetCurrentEventData(shared_ptr<EventData> eventData)
{
	_currentEventData = eventData;

	if (_currentEventData->conn == _listenEventData->conn)
	{
		ASSERT(0);
	}
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

void CMongooseExample_MFCDlg::SetNeedDeleteMgr()
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
	dlg->SetNeedDeleteMgr();

	dlg->AppendMsg(L"定时器");
}

void CMongooseExample_MFCDlg::OnBtnCreatetimer()
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
		AppendMsg(L"定时器事件循环结束");
	}).detach();

	/*mg_timer* timer = */mg_timer_add(mgr, 2000, MG_TIMER_ONCE/*一次性*/, timer_fn, this);
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
		tmpStr.Format(L"TCP服务端连接已准备 local:%s", GenerateIPPortString(conn->loc));
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_RESOLVE:
	{
		tmpStr.Format(L"MG_EV_RESOLVE remote:%s local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_ACCEPT:
	{
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

		// 保存当前连接
		shared_ptr<EventData> eventData = make_shared<EventData>(listenEventData->dlg);
		eventData->conn = conn;
		listenEventData->dlg->OnSetCurrentEventData(eventData);
	}
	break;
	case MG_EV_CLOSE:
	{
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

		eventData->dlg->OnDisconnectServer();
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

		if (eventData->dlg->IsUseSSL())
		{
			mg_tls_opts tlsOpts;
			memset(&tlsOpts, 0, sizeof(mg_tls_opts));
			mg_tls_init(conn, &tlsOpts);
		}
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
	case MG_EV_WS_MSG:
	{
		struct mg_ws_message* wm = (struct mg_ws_message*)ev_data;

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
	_currentEventData->conn->is_client = true;
	mg_resolve(_currentEventData->conn, url);
#endif
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

			const size_t len = 1024 * 10;
			char* msg = new char[len]{0};
			memset(msg, 'T', len - 1);

			if (_isWebsocket)
			{
				size_t ret = mg_ws_send(_currentEventData->conn, msg, len, WEBSOCKET_OP_BINARY);
				if (ret)
				{
					CString tmpStr;
					tmpStr.Format(L"发送%u字节数据 实际总大小:%u", len, ret);
					AppendMsg(tmpStr);
				}
				else
				{
					AppendMsg(L"发送数据失败");
				}
			}
			else
			{
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
			}

			delete[] msg;
		}
	}).detach();
}

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
		tmpStr.Format(L"新客户端连接 remote:%s", GenerateIPPortString(conn->rem));
		listenEventData->dlg->AppendMsg(tmpStr);

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


static void OnWebsocketServerEvent(struct mg_connection* conn, int ev, void* ev_data, void* fn_data)
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
		tmpStr.Format(L"新客户端连接 remote:%s", GenerateIPPortString(conn->rem));
		listenEventData->dlg->AppendMsg(tmpStr);

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
		break;
	case MG_EV_CLOSE:
	{
		tmpStr.Format(L"与客户端%s的连接断开", GenerateIPPortString(conn->rem));
		listenEventData->dlg->AppendMsg(tmpStr);

		listenEventData->dlg->OnDisconnectClient(conn);
	}
		break;
	case MG_EV_HTTP_MSG:
	{
		mg_http_message* hm = (mg_http_message*)ev_data;
		if (mg_http_match_uri(hm, "/websocket")) {
			// Upgrade to websocket. From now on, a connection is a full-duplex
			// Websocket connection, which will receive MG_EV_WS_MSG events.
			mg_ws_upgrade(conn, hm, NULL);

			tmpStr.Format(L"客户端升级websocket remote:%s", GenerateIPPortString(conn->rem));
			listenEventData->dlg->AppendMsg(tmpStr);

			// 保存当前连接
			shared_ptr<EventData> eventData = make_shared<EventData>(listenEventData->dlg);
			eventData->conn = conn;
			listenEventData->dlg->OnSetCurrentEventData(eventData);
		}
		else if (mg_http_match_uri(hm, "/api/getA"))
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
	case MG_EV_WS_OPEN:
	{
		CString tmpStr;
		tmpStr.Format(L"与客户端remote:%s websocket协议成功", GenerateIPPortString(conn->rem));
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_WS_MSG:
	{
		// Got websocket frame. Received data is wm->data. Echo it back!
		struct mg_ws_message* wm = (struct mg_ws_message*)ev_data;
		tmpStr.Format(L"收到MG_EV_WS_MSG数据 大小:%u", wm->data.len);
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_WS_CTL:
	break;
	default:
	{
		tmpStr.Format(L"OnWebsocketServerEvent unhandle ev:%d", ev);
		listenEventData->dlg->AppendMsg(tmpStr);
	}
	break;
	}
}

void CMongooseExample_MFCDlg::OnBtnWebsocketServer()
{
	_isNeedDeleteMgr = false;
	_isWebsocket = true;

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
		AppendMsg(L"Websocket服务端事件循环结束");
	}).detach();

	CString tmpStr;
	_editPort.GetWindowText(tmpStr);
	const int port = _wtoi(tmpStr);
	CStringA url;
	if (IsUseSSL())
	{
		url.Format("wss://0.0.0.0:%d", port);
	}
	else
	{
		url.Format("ws://0.0.0.0:%d", port);
	}

	_listenEventData = make_shared<EventData>(this);
	_listenEventData->conn = mg_http_listen(mgr, url, OnWebsocketServerEvent, _listenEventData.get());
	if (!_listenEventData->conn)
	{
		AppendMsg(L"Websocket开始监听失败");
		_isNeedDeleteMgr = true;
		return;
	}

	AppendMsg(L"Websocket开始监听");
}

void CMongooseExample_MFCDlg::OnBtnWebsocketServerStop()
{
	if (_listenEventData)
	{
		_listenEventData->conn->is_draining = true;
		AppendMsg(L"Websocket 服务端停止");
	}

	// 关闭事件循环
	_isNeedDeleteMgr = true;

	_isWebsocket = false;
}

static void OnWebsocketClientEvent(struct mg_connection* conn, int ev, void* ev_data, void* fn_data) 
{
	EventData* eventData = (EventData*)fn_data;
	CString tmpStr;

	if (!eventData->dlg)
	{
		return;
	}

	switch (ev)
	{
	case MG_EV_ERROR:
	{
		CString tmpStr;
		tmpStr.Format(L"Websocket客户端发生错误 remote:%s local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		eventData->dlg->AppendMsg(tmpStr);

		eventData->dlg->OnDisconnectServer();
	}
	break;
	case MG_EV_POLL:
		break;
	case MG_EV_OPEN:
	{
		CString tmpStr;
		tmpStr.Format(L"Websocket客户端初始化完成 local:%s", GenerateIPPortString(conn->loc));
		eventData->dlg->AppendMsg(tmpStr);
		break;
	}
	break;
	case MG_EV_CONNECT:
	{
		CString tmpStr;
		tmpStr.Format(L"与服务端remote:%s连接成功 local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		eventData->dlg->AppendMsg(tmpStr);

		if (eventData->dlg->IsUseSSL())
		{
			mg_tls_opts tlsOpts;
			memset(&tlsOpts, 0, sizeof(mg_tls_opts));
			mg_tls_init(conn, &tlsOpts);
		}
	}
	break;
	case MG_EV_RESOLVE:
	{
		CString tmpStr;
		tmpStr.Format(L"MG_EV_RESOLVE remote:%s local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		eventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_READ:
	case MG_EV_WRITE:
		break;
	case MG_EV_CLOSE:
	{
		CString tmpStr;
		tmpStr.Format(L"与服务端remote:%s连接断开 local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		eventData->dlg->AppendMsg(tmpStr);

		eventData->dlg->OnDisconnectServer();
	}
	break;
	case MG_EV_WS_OPEN:
	{
		CString tmpStr;
		tmpStr.Format(L"与服务端remote:%s websocket协议成功 local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		eventData->dlg->AppendMsg(tmpStr);
	}
	break;
	case MG_EV_WS_MSG:
	{
		struct mg_ws_message* wm = (struct mg_ws_message*)ev_data;
		tmpStr.Format(L"收到MG_EV_WS_MSG数据 大小:%u", wm->data.len);
		eventData->dlg->AppendMsg(tmpStr);
	}
	break;
	default:
	{
		tmpStr.Format(L"OnWebsocketClientEvent unhandle ev:%d", ev);
		eventData->dlg->AppendMsg(tmpStr);
	}
		break;
	}
}

void CMongooseExample_MFCDlg::OnBtnWebsocketConnect()
{
	_isNeedDeleteMgr = false;
	_isWebsocket = true;

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
		AppendMsg(L"Websocket客户端事件循环结束");
	}).detach();

	CStringA url;
	if (IsUseSSL())
	{
		url.Format("wss://%s:%d/websocket", remoteIP.c_str(), remotePort);
	}
	else
	{
		url.Format("ws://%s:%d/websocket", remoteIP.c_str(), remotePort);
	}
	CString strLog;
	strLog.Format(L"开始连接服务端：%s", S2Unicode(url).c_str());
	AppendMsg(strLog);

	_currentEventData = make_shared<EventData>(this);
	_currentEventData->conn = mg_ws_connect(mgr, url, OnWebsocketClientEvent, _currentEventData.get(), nullptr);
	if (nullptr == _currentEventData->conn)
	{
		_isNeedDeleteMgr = true;
		AppendMsg(L"mg_ws_connect失败");
		return;
	}
}

void CMongooseExample_MFCDlg::OnBtnWebsocketDisconnectServer()
{
	if (_currentEventData && _currentEventData->conn)
	{
		AppendMsg(L"客户端手动断开连接");

		_currentEventData->conn->is_draining = true;
	}

	// 关闭事件循环
	_isNeedDeleteMgr = true;

	_isWebsocket = false;
}
