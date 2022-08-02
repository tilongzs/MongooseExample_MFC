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
#define DEFAULT_SOCKET_IP "127.0.0.1"
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
	ssl_ctx_st* ssl_ctx = nullptr;
	ssl_st* ssl = nullptr;
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
	DDX_Control(pDX, IDC_EDIT_MSG, _editRecv);
	DDX_Control(pDX, IDC_EDIT_PORT, _editPort);
	DDX_Control(pDX, IDC_EDIT_PORT_REMOTE, _editRemotePort);
	DDX_Control(pDX, IDC_CHECK_SSL, _btnUseSSL);
	DDX_Control(pDX, IDC_BUTTON_HTTP_SERVER, _btnHTTPServer);
	DDX_Control(pDX, IDC_BUTTON_HTTP_SERVER_STOP, _btnStopHttpServer);
}

BEGIN_MESSAGE_MAP(CMongooseExample_MFCDlg, CDialogEx)
	ON_WM_PAINT()
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
	ON_BN_CLICKED(IDC_BUTTON_HTTP_POST, &CMongooseExample_MFCDlg::OnBtnHttpPost)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_PUT, &CMongooseExample_MFCDlg::OnBtnHttpPut)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_POST_FILE, &CMongooseExample_MFCDlg::OnBtnHttpPostFile)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_DEL, &CMongooseExample_MFCDlg::OnBtnHttpDel)
END_MESSAGE_MAP()

BOOL CMongooseExample_MFCDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE);

	_editPort.SetWindowText(L"23300");
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

void CMongooseExample_MFCDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
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

void CMongooseExample_MFCDlg::OnTCPDisconnect(mg_connection* conn)
{
	if (_currentEventData && _currentEventData->conn == conn)
	{
		_currentEventData = nullptr;
	}
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

// static void OnServerWrite(bufferevent* bev, void* param)
// {
// 	EventData* eventData = (EventData*)param;
// 
// 	eventData->dlg->AppendMsg(L"OnServerWrite");
// }

// static void OnServerRead(bufferevent* bev, void* param)
// {
// 	EventData* eventData = (EventData*)param;
// 
// 	evbuffer* input = bufferevent_get_input(bev);
// 	size_t sz = evbuffer_get_length(input);
// 	if (sz > 0)
// 	{
// 		char* buffer = new char[sz]{0};
// 		bufferevent_read(bev, buffer, sz);
// 
// 		CString tmpStr;
// 		tmpStr.Format(L"threadID:%d 收到%u字节", this_thread::get_id(), sz);
// 		eventData->dlg->AppendMsg(tmpStr);		
// 
// 		delete[] buffer;
// 	}
// }

// static void OnServerEvent(bufferevent* bev, short events, void* param)
// {
// 	EventData* eventData = (EventData*)param;
// 
// 	if (events & BEV_EVENT_EOF) 
// 	{
// 		eventData->dlg->AppendMsg(L"BEV_EVENT_EOF 连接关闭");
// 		if (eventData->ssl)
// 		{
// 			SSL_shutdown(eventData->ssl);
// 		}
// 	}
// 	else if (events & BEV_EVENT_ERROR)
// 	{
// 		CString tmpStr;
// 		if (events & BEV_EVENT_READING)
// 		{
// 			tmpStr.Format(L"BEV_EVENT_ERROR BEV_EVENT_READING错误errno:%d", errno);
// 		}
// 		else if (events & BEV_EVENT_WRITING)
// 		{
// 			tmpStr.Format(L"BEV_EVENT_ERROR BEV_EVENT_WRITING错误errno:%d", errno);
// 		}
// 	
// 		eventData->dlg->AppendMsg(tmpStr);
// 	}
// }

// static void OnServerEventAccept(evconnlistener* listener, evutil_socket_t fd, sockaddr* sa, int socklen, void* param)
// {
// 	EventData* eventData = (EventData*)param;
// 	event_base* eventBase = evconnlistener_get_base(listener);
// 
// 	int bufLen = SINGLE_PACKAGE_SIZE;
// 	int ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*)&bufLen, sizeof(int));
// 	ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char*)&bufLen, sizeof(int));
// 	linger l;
// 	l.l_onoff = 1;
// 	l.l_linger = 0;
// 	ret = setsockopt(fd, SOL_SOCKET, SO_LINGER, (const char*)&l, sizeof(l));
// 
// 	//构造一个bufferevent
// 	bufferevent* bev = nullptr;
// 	if (eventData->dlg->IsUseSSL())
// 	{
// 		// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
// 		eventData->ssl = SSL_new(eventData->ssl_ctx);
// 		SSL_set_fd(eventData->ssl, fd);
// 		bev = bufferevent_openssl_socket_new(eventBase, fd, eventData->ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
// 	}
// 	else
// 	{
// 		bev = bufferevent_socket_new(eventBase, fd, BEV_OPT_CLOSE_ON_FREE);
// 	}
// 
// 	if (!bev) 
// 	{
// 		eventData->dlg->AppendMsg(L"bufferevent_socket_new失败");
// 		event_base_loopbreak(eventBase);
// 		return;
// 	}
// 	eventData->bev = bev;
// 
// 	// 修改读写上限
// 	ret = bufferevent_set_max_single_read(bev, SINGLE_PACKAGE_SIZE);
// 	if (ret != 0)
// 	{
// 		eventData->dlg->AppendMsg(L"bufferevent_set_max_single_read失败");
// 	}
// 	ret = bufferevent_set_max_single_write(bev, SINGLE_PACKAGE_SIZE);
// 	if (ret != 0)
// 	{
// 		eventData->dlg->AppendMsg(L"bufferevent_set_max_single_write失败");
// 	}
// 
// 	//绑定读事件回调函数、写事件回调函数、错误事件回调函数
// 	bufferevent_setcb(bev, OnServerRead, OnServerWrite, OnServerEvent, eventData);
// 
// 	bufferevent_enable(bev, EV_READ | EV_WRITE);
// 
// 	string remoteIP;
// 	int remotePort;
// 	ConvertIPPort(*(sockaddr_in*)sa, remoteIP, remotePort);
// 	CString tmpStr;
// 	tmpStr.Format(L"threadID:%d 新客户端%s:%d 连接", this_thread::get_id(), S2Unicode(remoteIP).c_str(), remotePort);
// 	eventData->dlg->AppendMsg(tmpStr);
// }

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
		tmpStr.Format(L"TCP服务端连接已准备 remote:%s local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		listenEventData->dlg->AppendMsg(tmpStr);
		break;
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

		listenEventData->dlg->OnTCPDisconnect(conn);
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
		listenEventData->dlg->AppendMsg(L"OnTCPEvent default");
		break;
	}
}

void CMongooseExample_MFCDlg::OnBtnListen()
{
	_isNeedClose = false;

	mg_mgr* mgr = new mg_mgr;
	mg_mgr_init(mgr);
	thread([&, mgr]
	{
		while (!_isNeedClose)
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
		_isNeedClose = true;
	}

	// 	event_config* cfg = event_config_new();
	// 	evthread_use_windows_threads();
	// 	event_config_set_num_cpus_hint(cfg, 8);
	// 	event_config_set_flag(cfg, EVENT_BASE_FLAG_STARTUP_IOCP);
	// 
	// 	event_base* eventBase = event_base_new_with_config(cfg);
	// 	if (!eventBase)
	// 	{
	// 		event_config_free(cfg);
	// 		AppendMsg(L"创建eventBase失败");
	// 		return;
	// 	}
	// 	event_config_free(cfg);
	// 	cfg = nullptr;
	// 
	// 	//创建、绑定、监听socket
	// 	CString tmpStr;
	// 	_editPort.GetWindowText(tmpStr);
	// 	const int port = _wtoi(tmpStr);
	// 
	// 	sockaddr_in localAddr = {0};
	// 	localAddr.sin_family = AF_INET;
	// 	localAddr.sin_port = htons(port);
	// 
	// 	EventData* eventData = new EventData;
	// 	eventData->dlg = this;
	// 
	// 	if (IsUseSSL())
	// 	{
	// 		/*
	// 			生成x.509证书
	// 			首选在安装好openssl的机器上创建私钥文件：server.key
	// 			> openssl genrsa -out server.key 2048
	// 			
	// 			得到私钥文件后我们需要一个证书请求文件：server.csr，将来你可以拿这个证书请求向正规的证书管理机构申请证书			
	// 			> openssl req -new -key server.key -out server.csr
	// 			
	// 			最后我们生成自签名的x.509证书（有效期365天）：server.crt			
	// 			> openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
	// 		*/
	// 		CString exeDir = GetModuleDir();
	// 		CString serverCrtPath = CombinePath(exeDir, L"../3rd/OpenSSL/server.crt");
	// 		CString serverKeyPath = CombinePath(exeDir, L"../3rd/OpenSSL/server.key");
	// 
	// 		// 引入之前生成好的私钥文件和证书文件
	// 		ssl_ctx_st* ssl_ctx = SSL_CTX_new(TLS_server_method());
	// 		if (!ssl_ctx)
	// 		{
	// 			AppendMsg(L"ssl_ctx new failed");
	// 			return;
	// 		}
	// 		int res = SSL_CTX_use_certificate_file(ssl_ctx, UnicodeToUTF8(serverCrtPath).c_str(), SSL_FILETYPE_PEM);
	// 		if (res != 1)
	// 		{
	// 			AppendMsg(L"SSL_CTX_use_certificate_file failed");
	// 			return;
	// 		}
	// 		res = SSL_CTX_use_PrivateKey_file(ssl_ctx, UnicodeToUTF8(serverKeyPath).c_str(), SSL_FILETYPE_PEM);
	// 		if (res != 1)
	// 		{
	// 			AppendMsg(L"SSL_CTX_use_PrivateKey_file failed");
	// 			return;
	// 		}
	// 		res = SSL_CTX_check_private_key(ssl_ctx);
	// 		if (res != 1)
	// 		{
	// 			AppendMsg(L"SSL_CTX_check_private_key failed");
	// 			return;
	// 		}
	// 
	// 		eventData->ssl_ctx = ssl_ctx;
	// 	}
	// 
	// 	_listener = evconnlistener_new_bind(eventBase, OnServerEventAccept, eventData,
	// 		LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
	// 		(sockaddr*)&localAddr, sizeof(localAddr));
	// 	if (!_listener)
	// 	{
	// 		AppendMsg(L"创建evconnlistener失败");
	// 				
	// 		event_base_free(eventBase);
	// 		delete eventData;
	// 		return;
	// 	}
	// 	_currentEventData = eventData;
	// 
	// 	thread([&, eventBase]
	// 	{
	// 		event_base_dispatch(eventBase); // 阻塞
	// 		AppendMsg(L"服务端socket event_base_dispatch线程 结束");
	// 	
	// 		evconnlistener_free(_listener);
	// 		delete _currentEventData;
	// 		_currentEventData = nullptr;
	// 		event_base_free(eventBase);		
	// 	}).detach();
}

void CMongooseExample_MFCDlg::OnBtnStopListen()
{
	if (_listenEventData)
	{
		AppendMsg(L"服务端手动停止监听");
		_listenEventData->conn->is_draining = true;
	}

	// 关闭事件循环
	_isNeedClose = true;
}

// static void OnClientWrite(bufferevent* bev, void* param)
// {
// 	EventData* eventData = (EventData*)param;
// 
// 	eventData->dlg->AppendMsg(L"OnClientWrite");
// }

// static void OnClientRead(bufferevent* bev, void* param)
// {
// 	EventData* eventData = (EventData*)param;
// 
// 	evbuffer* input = bufferevent_get_input(bev);
// 	size_t sz = evbuffer_get_length(input);
// 	if (sz > 0)
// 	{
// 		char* buffer = new char[sz] {0};
// 		bufferevent_read(bev, buffer, sz);
// 
// 		CString tmpStr;
// 		tmpStr.Format(L"threadID:%d 收到%u字节", this_thread::get_id(), sz);
// 		eventData->dlg->AppendMsg(tmpStr);
// 
// 		delete[] buffer;
// 	}
// }

// static void OnClientEvent(bufferevent* bev, short events, void* param)
// {
// 	EventData* eventData = (EventData*)param;
// 
// 	if (events & BEV_EVENT_CONNECTED)
// 	{
// 		eventData->dlg->AppendMsg(L"连接服务端成功");
// 	}
// 	else if (events & BEV_EVENT_EOF) 
// 	{
// 		eventData->dlg->AppendMsg(L"BEV_EVENT_EOF 连接关闭");
// 	}
// 	else if (events & BEV_EVENT_ERROR)
// 	{
// 		CString tmpStr;
// 		if (events & BEV_EVENT_READING)
// 		{
// 			tmpStr.Format(L"BEV_EVENT_ERROR BEV_EVENT_READING错误errno:%d", errno);
// 		}
// 		else if (events & BEV_EVENT_WRITING)
// 		{
// 			tmpStr.Format(L"BEV_EVENT_ERROR BEV_EVENT_WRITING错误errno:%d", errno);
// 		}
// 		eventData->dlg->AppendMsg(tmpStr);
// 	}
// }

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

		eventData->dlg->OnTCPDisconnect(conn);
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
	_isNeedClose = false;

	// 使用指定的本地IP、端口
	CString tmpStr;
	_editPort.GetWindowText(tmpStr);
	const int localPort = _wtoi(tmpStr);
	SOCKADDR_IN localAddr;
	ConvertIPPort(DEFAULT_SOCKET_IP, localPort, localAddr);

	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);
	SOCKADDR_IN remoteAddr;
	ConvertIPPort(DEFAULT_SOCKET_IP, remotePort, remoteAddr);

	if (localPort == remotePort)
	{
		AppendMsg(L"当远程和本地IP相同时，端口不能也相同！");
		return;
	}

	mg_mgr* mgr = new mg_mgr;
	mg_mgr_init(mgr);
	thread([&, mgr]
	{
		while (!_isNeedClose)
		{
			mg_mgr_poll(mgr, 1);
		}

		mg_mgr_free(mgr);
		AppendMsg(L"TCP客户端事件循环结束");
	}).detach();

	shared_ptr<EventData> eventData = make_shared<EventData>(this);
#ifdef _USE_RANDOM_LOCALPORT
		// 使用任意本地端口连接服务端
	CStringA url;
	url.Format("tcp://127.0.0.1:%d", remotePort);
	CString strLog;
	strLog.Format(L"开始连接服务端：%s", S2Unicode(url).c_str());
	AppendMsg(strLog);
	eventData->conn = mg_connect(mgr, url, OnTCPClientEvent, this);
#else
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
		_isNeedClose = true;
		::closesocket(sockfd);
		AppendMsg(L"TCP客户端setsockopt SO_LINGER失败");
		return;
	}

	if (0 != ::bind(sockfd, (sockaddr*)&localAddr, sizeof(sockaddr)))
	{
		_isNeedClose = true;
		::closesocket(sockfd);
		AppendMsg(L"绑定本地端口失败");
		return;
	}

	if (0 != ::connect(sockfd, (sockaddr*)&remoteAddr, sizeof(sockaddr)))
	{
		_isNeedClose = true;
		::closesocket(sockfd);
		AppendMsg(L"连接服务端失败");
		return;
	}

	eventData->conn = mg_wrapfd(mgr, sockfd, OnTCPClientEvent, eventData.get());
	if (nullptr == eventData->conn)
	{
		_isNeedClose = true;
		::closesocket(sockfd);
		AppendMsg(L"mg_wrapfd失败");
		return;
	}
#endif

	_currentEventData = eventData;

	tmpStr.Format(L"与服务端remote:%s:%d连接成功 local:%s:%d", S2Unicode(DEFAULT_SOCKET_IP).c_str(), remotePort, S2Unicode(DEFAULT_SOCKET_IP).c_str(), localPort);
	AppendMsg(tmpStr);
}

void CMongooseExample_MFCDlg::OnBtnDisconnectServer()
{
	if (_currentEventData && _currentEventData->conn)
	{
		AppendMsg(L"客户端手动断开连接");

		_currentEventData->conn->is_draining = true;
	}

	// 关闭事件循环
	_isNeedClose = true;
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
	case MG_EV_POLL:
		break;
	case MG_EV_OPEN:
	{
		CString tmpStr;
		tmpStr.Format(L"UDP已准备 remote:%s local:%s", GenerateIPPortString(conn->rem), GenerateIPPortString(conn->loc));
		listenEventData->dlg->AppendMsg(tmpStr);
		break;
	}
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
		CString tmpStr;
		tmpStr.Format(L"与客户端%s的连接断开", GenerateIPPortString(conn->rem));
		listenEventData->dlg->AppendMsg(tmpStr);

		listenEventData->dlg->OnTCPDisconnect(conn);
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
		listenEventData->dlg->AppendMsg(L"OnTCPEvent default");
		break;
	}
}

void CMongooseExample_MFCDlg::OnBtnUdpBind()
{
	_isNeedClose = false;

	mg_mgr* mgr = new mg_mgr;
	mg_mgr_init(mgr);
	thread([&, mgr]
	{
		while (!_isNeedClose)
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
		_isNeedClose = true;
	}
}

void CMongooseExample_MFCDlg::OnBtnUdpSendMsg()
{
	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	sockaddr_in remoteAddr = { 0 };
	if (!ConvertIPPort(DEFAULT_SOCKET_IP, remotePort, remoteAddr))
	{
		AppendMsg(L"IP地址无效");
	}

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
	_isNeedClose = true;
}

// static void OnHTTP_API_getA(evhttp_request* req, void* arg)
// {
// 	CMongooseExample_MFCDlg* dlg = (CMongooseExample_MFCDlg*)arg;
// 	// http://127.0.0.1:23300/api/getA?q=test&s=some+thing
// 
// 	const evhttp_uri* evURI = evhttp_request_get_evhttp_uri(req);	
// 	const char* uri = evhttp_request_get_uri(req);// 获取请求uri "/api/getA?q=test&s=some+thing"
// 	//evhttp_uri* evURI = evhttp_uri_parse(uri);// 解码uri
// 	if (!evURI)
// 	{
// 		evhttp_send_error(req, HTTP_BADREQUEST, NULL);
// 		return;
// 	}
// // 	char uri[URL_MAX] = {0};
// // 	evhttp_uri_join((evhttp_uri*)evURI, uri, URL_MAX);// 获取请求uri "/api/getA?q=test&s=some+thing"
// 
// 	const char* path = evhttp_uri_get_path(evURI); // 获取uri中的path部分 "/api/getA"
// 	if (!path)
// 	{
// 		path = "/";
// 	}
// 
// 	const char* query = evhttp_uri_get_query(evURI); // 获取uri中的参数部分 "q=test&s=some+thing"
// 	const char* scheme = evhttp_uri_get_scheme(evURI); // nullptr
// 	const char* fragment = evhttp_uri_get_fragment(evURI); // nullptr
// 
// 	// 查询指定参数的值
// 	evkeyvalq params = { 0 };
// 	evhttp_parse_query_str(query, &params);
// 	const char* value = evhttp_find_header(&params, "s"); // "some thing"
// 	value = evhttp_find_header(&params, "q"); // "test"
// 
// 	// 回复
// 	evbuffer_add_printf(req->output_buffer, UnicodeToUTF8(L"谢谢！Thanks use getA").c_str());
// 	//evbuffer_add(req->output_buffer, s, strlen(s));
// 	evhttp_send_reply(req, HTTP_OK, "OK", nullptr);
// 
// 	CString strMsg;
// 	strMsg.Format(L"收到%s:%d PutA接口请求", CString(req->remote_host), req->remote_port);
// 	dlg->AppendMsg(strMsg);
// }

// static void OnHTTP_API_postA(evhttp_request* req, void* arg)
// {
// 	CMongooseExample_MFCDlg* dlg = (CMongooseExample_MFCDlg*)arg;
// 	// http://127.0.0.1:23300/api/postA?q=test&s=some+thing
// 
// 	const evhttp_uri* evURI = evhttp_request_get_evhttp_uri(req);
// 	const char* uri = evhttp_request_get_uri(req);// 获取请求uri "/api/postA?q=test&s=some+thing"
// 	//evhttp_uri* evURI = evhttp_uri_parse(uri);// 解码uri
// 	if (!evURI)
// 	{
// 		evhttp_send_error(req, HTTP_BADREQUEST, NULL);
// 		return;
// 	}
// 	// 	char uri[URL_MAX] = {0};
// 	// 	evhttp_uri_join((evhttp_uri*)evURI, uri, URL_MAX);// 获取请求uri "/api/posttA?q=test&s=some+thing"
// 
// 	const char* path = evhttp_uri_get_path(evURI); // 获取uri中的path部分 "/api/postA"
// 	if (!path)
// 	{
// 		path = "/";
// 	}
// 
// 	const char* query = evhttp_uri_get_query(evURI); // 获取uri中的参数部分 "q=test&s=some+thing"
// 	const char* fragment = evhttp_uri_get_fragment(evURI);
// 
// 	// 查询指定参数的值
// 	evkeyvalq params = { 0 };
// 	evhttp_parse_query_str(query, &params);
// 	const char* value = evhttp_find_header(&params, "s"); // "some thing"
// 	value = evhttp_find_header(&params, "q"); // "test"
// 
// 	// 获取Headers
// 	evkeyvalq* headers = evhttp_request_get_input_headers(req);
// 	value = evhttp_find_header(headers, "Host");
// 	value = evhttp_find_header(headers, "BodySize");
// 	size_t bodySize = atoi(value);
// 
// 	// 获取数据长度
// 	size_t len = evbuffer_get_length(req->input_buffer);
// 	if (len != bodySize)
// 	{
// 		evhttp_send_reply(req, HTTP_NOCONTENT, "wrong bodySize", nullptr);
// 		CString strMsg;
// 		strMsg.Format(L"bodySize:%u 但实际收到PostA接口%u字节数据", bodySize, len);
// 		dlg->AppendMsg(strMsg);
// 		return;
// 	}
// 
// 	if (len > 0)
// 	{
// 		// 获取数据指针
// 		unsigned char* data = evbuffer_pullup(req->input_buffer, len);
// 
// 		// 处理数据...
// 
// 		// 清空数据
// 		evbuffer_drain(req->input_buffer, len);
// 	}
// 
// 	// 模拟时延/超时
// 	//this_thread::sleep_for(chrono::seconds(5));
// 
// 	// 回复
// 	const size_t bufSize = 65535 * 10;
// 	char* postBuf = new char[bufSize] {'B'};
// 	evbuffer_add(req->output_buffer, postBuf, bufSize);
// 	delete[] postBuf;
// 	evhttp_send_reply(req, HTTP_OK, nullptr, nullptr);
// 
// 	CString strMsg;
// 	strMsg.Format(L"收到PostA接口%u字节数据", len);
// 	dlg->AppendMsg(strMsg);
// }

// static void OnHTTP_API_postFileA(evhttp_request* req, void* arg)
// {
// 	CMongooseExample_MFCDlg* dlg = (CMongooseExample_MFCDlg*)arg;
// 	// http://127.0.0.1:23300/api/postFileA?q=test&s=some+thing
// 
// 	const evhttp_uri* evURI = evhttp_request_get_evhttp_uri(req);
// 	const char* uri = evhttp_request_get_uri(req);// 获取请求uri "/api/postFileA?q=test&s=some+thing"
// 	//evhttp_uri* evURI = evhttp_uri_parse(uri);// 解码uri
// 	if (!evURI)
// 	{
// 		evhttp_send_error(req, HTTP_BADREQUEST, NULL);
// 		return;
// 	}
// 	// 	char uri[URL_MAX] = {0};
// 	// 	evhttp_uri_join((evhttp_uri*)evURI, uri, URL_MAX);// 获取请求uri "/api/postFileA?q=test&s=some+thing"
// 
// 	const char* path = evhttp_uri_get_path(evURI); // 获取uri中的path部分 "/api/postFileA"
// 	if (!path)
// 	{
// 		path = "/";
// 	}
// 
// 	const char* query = evhttp_uri_get_query(evURI); // 获取uri中的参数部分 "q=test&s=some+thing"
// 	const char* fragment = evhttp_uri_get_fragment(evURI);
// 
// 	// 查询指定参数的值
// 	evkeyvalq params = { 0 };
// 	evhttp_parse_query_str(query, &params);
// 	const char* value = evhttp_find_header(&params, "s"); // "some thing"
// 	value = evhttp_find_header(&params, "q"); // "test"
// 
// 	// 获取Headers
// 	evkeyvalq* headers = evhttp_request_get_input_headers(req);
// 	value = evhttp_find_header(headers, "FileSize");
// 	size_t fileSize = atoi(value);
// 	wstring fileName = UTF8ToUnicode(evhttp_find_header(headers, "FileName"));
// 
// 	// 获取数据长度
// 	size_t len = evbuffer_get_length(req->input_buffer);
//  	if (len != fileSize)
//  	{
//  		evhttp_send_reply(req, HTTP_NOCONTENT, "wrong bodySize", nullptr);
//  		CString strMsg;
//  		strMsg.Format(L"fileName:%s fileSize:%u 但实际收到PostFileA接口%u字节数据", fileName.c_str(), fileSize, len);
//  		dlg->AppendMsg(strMsg);
//  		return;
//  	}
// 
// 	if (len > 0)
// 	{
// 		// 获取数据指针
// 		unsigned char* data = evbuffer_pullup(req->input_buffer, len);
// 
// 		// 处理数据...
// 
// 		// 清空数据
// 		evbuffer_drain(req->input_buffer, len);
// 	}
// 
// 	// 模拟时延/超时
// 	//this_thread::sleep_for(chrono::seconds(5));
// 
// 	// 回复
// 	const size_t bufSize = 65535 * 10;
// 	char* postBuf = new char[bufSize] {'B'};
// 	evbuffer_add(req->output_buffer, postBuf, bufSize);
// 	delete[] postBuf;
// 	evhttp_send_reply(req, HTTP_OK, nullptr, nullptr);
// 
// 	CString strMsg;
// 	strMsg.Format(L"收到PostFileA接口 %s %u字节数据", fileName.c_str(), len);
// 	dlg->AppendMsg(strMsg);
// }


// static void OnHTTP_API_putA(evhttp_request* req, void* arg)
// {
// 	CMongooseExample_MFCDlg* dlg = (CMongooseExample_MFCDlg*)arg;
// 
// 	size_t len = evbuffer_get_length(req->input_buffer);
// 	if (len > 0)
// 	{
// 		// 获取数据指针
// 		unsigned char* data = evbuffer_pullup(req->input_buffer, len);
// 
// 		// 处理数据...
// 
// 		// 清空数据
// 		evbuffer_drain(req->input_buffer, len);
// 	}
// 
// 	const char* s = "This is the test buf";
// 	evbuffer_add(req->output_buffer, s, strlen(s));
// 	evhttp_send_reply(req, 200, "OK", nullptr);
// 
// 	CString strMsg;
// 	strMsg.Format(L"收到PutA接口%u字节数据", len);
// 	dlg->AppendMsg(strMsg);
// }
// 
// static void OnHTTP_API_delA(evhttp_request* req, void* arg)
// {
// 	CMongooseExample_MFCDlg* dlg = (CMongooseExample_MFCDlg*)arg;
// 
// 	size_t len = evbuffer_get_length(req->input_buffer);
// 	if (len > 0)
// 	{
// 		// 获取数据指针
// 		unsigned char* data = evbuffer_pullup(req->input_buffer, len);
// 
// 		// 处理数据...
// 
// 		// 清空数据
// 		evbuffer_drain(req->input_buffer, len);
// 	}
// 
// 	const char* s = "This is the test buf";
// 	evbuffer_add(req->output_buffer, s, strlen(s));
// 	evhttp_send_reply(req, 200, "OK", nullptr);
// 
// 	CString strMsg;
// 	strMsg.Format(L"收到DelA接口%u字节数据", len);
// 	dlg->AppendMsg(strMsg);
// }

// static void OnHTTPUnmatchedRequest(evhttp_request* req, void* arg)
// {
// 	CMongooseExample_MFCDlg* dlg = (CMongooseExample_MFCDlg*)arg;
// 
// 	const char* s = "This is the generic buf";
// 	evbuffer_add(req->output_buffer, s, strlen(s));
// 	evhttp_send_reply(req, 200, "OK", nullptr);
// }

// static bufferevent* OnHTTPSetBev(struct event_base* base, void* arg)
// {
// 	EventData* eventData = (EventData*)arg;
// 
// 	eventData->bev = bufferevent_openssl_socket_new(base,
// 		-1,
// 		SSL_new(eventData->ssl_ctx),
// 		BUFFEREVENT_SSL_ACCEPTING,
// 		BEV_OPT_CLOSE_ON_FREE);
// 	return eventData->bev;
// }

void CMongooseExample_MFCDlg::OnBtnHttpServer()
{
	// 	event_config* cfg = event_config_new();
	// 	evthread_use_windows_threads();
	// 	event_config_set_num_cpus_hint(cfg, 8);
	// 	event_config_set_flag(cfg, EVENT_BASE_FLAG_STARTUP_IOCP);
	// 
	// 	event_base* eventBase = event_base_new_with_config(cfg);
	// 	if (!eventBase)
	// 	{
	// 		event_config_free(cfg);
	// 		AppendMsg(L"创建eventBase失败");
	// 		return;
	// 	}
	// 	event_config_free(cfg);
	// 	cfg = nullptr;
	// 
	// 	_httpServer = evhttp_new(eventBase);
	// 	if (!_httpServer)
	// 	{
	// 		AppendMsg(L"创建http_server失败");
	// 
	// 		event_base_free(eventBase);
	// 		return;
	// 	}
	// 
	// 	// 连接参数设置
	// 	evhttp_set_max_headers_size(_httpServer, HTTP_MAX_HEAD_SIZE);
	// 	evhttp_set_max_body_size(_httpServer, HTTP_MAX_BODY_SIZE);
	// 	evhttp_set_max_connections(_httpServer, 10000 * 100);
	// 	evhttp_set_timeout(_httpServer, 10);//设置闲置连接自动断开的超时时间(s)
	// 
	// 	_btnHTTPServer.EnableWindow(FALSE);
	// 	_btnStopHttpServer.EnableWindow(TRUE);
	// 
	// 	//创建、绑定、监听socket
	// 	CString tmpStr;
	// 	_editPort.GetWindowText(tmpStr);
	// 	const int port = _wtoi(tmpStr);
	// 
	// 	sockaddr_in localAddr = { 0 };
	// 	localAddr.sin_family = AF_INET;
	// 	localAddr.sin_port = htons(port);
	// 
	// 	EventData* eventData = new EventData;
	// 	eventData->dlg = this;
	// 
	// 	if (IsUseSSL())
	// 	{
	// 		CString exeDir = GetModuleDir();
	// 		CString serverCrtPath = CombinePath(exeDir, L"../3rd/OpenSSL/server.crt");
	// 		CString serverKeyPath = CombinePath(exeDir, L"../3rd/OpenSSL/server.key");
	// 
	// 		// 引入之前生成好的私钥文件和证书文件
	// 		ssl_ctx_st* ssl_ctx = SSL_CTX_new(TLS_server_method());
	// 		if (!ssl_ctx)
	// 		{
	// 			AppendMsg(L"ssl_ctx new failed");
	// 			return;
	// 		}
	// 
	// 		int res = SSL_CTX_use_certificate_chain_file(ssl_ctx, UnicodeToUTF8(serverCrtPath).c_str());
	// 		if (res != 1)
	// 		{
	// 			AppendMsg(L"SSL_CTX_use_certificate_chain_file failed");
	// 			return;
	// 		}
	// 		res = SSL_CTX_use_PrivateKey_file(ssl_ctx, UnicodeToUTF8(serverKeyPath).c_str(), SSL_FILETYPE_PEM);
	// 		if (res != 1)
	// 		{
	// 			AppendMsg(L"SSL_CTX_use_PrivateKey_file failed");
	// 			return;
	// 		}
	// 		res = SSL_CTX_check_private_key(ssl_ctx);
	// 		if (res != 1)
	// 		{
	// 			AppendMsg(L"SSL_CTX_check_private_key failed");
	// 			return;
	// 		}
	// 
	// 		eventData->ssl_ctx = ssl_ctx;
	// 
	// 		evhttp_set_bevcb(_httpServer, OnHTTPSetBev, eventData);
	// 	}
	// 
	// 	_httpSocket = evhttp_bind_socket_with_handle(_httpServer, "0.0.0.0", port);
	// 	if (!_httpSocket)
	// 	{
	// 		AppendMsg(L"创建evhttp_bind_socket失败");
	// 		delete eventData;
	// 		return;
	// 	}	
	// 
	// 	/*
	// 		URI like http://127.0.0.1:23300/api/getA?q=test&s=some+thing
	// 		The first entry is: key="q", value="test"
	// 		The second entry is: key="s", value="some thing"
	// 	*/		
	// 	evhttp_set_cb(_httpServer, "/api/getA", OnHTTP_API_getA, this);
	// 	evhttp_set_cb(_httpServer, "/api/postA", OnHTTP_API_postA, this);
	// 	evhttp_set_cb(_httpServer, "/api/postFileA", OnHTTP_API_postFileA, this);
	// 	evhttp_set_cb(_httpServer, "/api/putA", OnHTTP_API_putA, this);
	// 	evhttp_set_cb(_httpServer, "/api/delA", OnHTTP_API_delA, this);
	// 	evhttp_set_gencb(_httpServer, OnHTTPUnmatchedRequest, this);
	// 		
	// 	AppendMsg(L"HTTP 服务端启动");
	// 	thread([&, eventData, eventBase]
	// 	{
	// 		event_base_dispatch(eventBase); // 阻塞
	// 
	// 		delete eventData;
	// 		evhttp_free(_httpServer);		
	// 	}).detach();
}

void CMongooseExample_MFCDlg::OnBtnStopHttpServer()
{
	// 	if (_httpServer && _httpSocket)
	// 	{
	// 		evhttp_del_accept_socket(_httpServer, _httpSocket);
	// 
	// 		AppendMsg(L"HTTP 服务端停止");
	// 		_btnHTTPServer.EnableWindow(TRUE);
	// 		_btnStopHttpServer.EnableWindow(FALSE);
	// 	}
}

// static void OnHttpResponseGetA(evhttp_request* req, void* arg)
// {
// 	HttpData* httpData = (HttpData*)arg;
// 
// 	if (req)
// 	{
// 		// 获取数据长度
// 		size_t len = evbuffer_get_length(req->input_buffer);
// 		if (len > 0)
// 		{
// 			// 获取数据指针
// 			unsigned char* data = evbuffer_pullup(req->input_buffer, len);
// 			char* responseStr = new char[len + 1]{ 0 };
// 			memcpy(responseStr, data, len);
// 
// 			CString strMsg;
// 			strMsg.Format(L"收到GetA接口回复：%s", UTF8ToUnicode(responseStr).c_str());
// 			httpData->dlg->AppendMsg(strMsg);
// 			delete[] responseStr;
// 
// 			// 清空数据
// 			evbuffer_drain(req->input_buffer, len);
// 			evhttp_request_free(req);
// 		}
// 	}
// 	else
// 	{
// 		httpData->dlg->AppendMsg(L"GetA失败");
// 	}
// 
// 	// 主动断开与服务器连接
// 	httpData->Free();
// }

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

// static void OnHttpResponsePostA(evhttp_request* req, void* arg)
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
// 		strMsg.Format(L"收到PostA接口回复%u字节数据", len);
// 		httpData->dlg->AppendMsg(strMsg);
// 	}
// 	else
// 	{
// 		httpData->dlg->AppendMsg(L"PostA失败");
// 	}	
// 
// 	// 主动断开与服务器连接
// 	//httpData->Free();
// }

void CMongooseExample_MFCDlg::OnBtnHttpPost()
{
	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	CString strURI;
	strURI.Format(L"http://127.0.0.1:%d/api/postA?q=test&s=some+thing", remotePort);
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
	// 	evhttp_connection_set_timeout(httpData->evConn, 3);// 设置超时时间(s)
	// 
	// 	evhttp_request* req = evhttp_request_new(OnHttpResponsePostA, httpData);
	// 
	// 	// 标准Header
	// 	evhttp_add_header(req->output_headers, "Connection", "keep-alive");
	// 	evhttp_add_header(req->output_headers, "Host", "localhost");
	// 
	// 	// 自定义Header
	// 	const size_t bufSize = 1024 * 1024; // 单次最大1GB（1024 * 1024 * 1024）
	// 	evhttp_add_header(req->output_headers, "bodySize", Int2Str(bufSize).c_str());
	// 
	// 	// 自定义Body数据
	// 	char* postBuf = new char[bufSize] {'A'};
	// 	evbuffer_add(req->output_buffer, postBuf, bufSize);
	// 	delete[] postBuf;
	// 
	// 	evhttp_make_request(httpData->evConn, req, EVHTTP_REQ_POST, "/api/postA?q=test&s=some+thing");
	// 
	// 	thread([&, eventBase, httpData]
	// 	{
	// 		event_base_dispatch(eventBase); // 阻塞
	// 		AppendMsg(L"客户端HttpPost event_base_dispatch线程 结束");
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

// static void OnHttpResponsePutA(evhttp_request* req, void* arg)
// {
// 	auto threadID = this_thread::get_id();
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
// 
// 		CString strMsg;
// 		strMsg.Format(L"收到PutA接口回复%u字节数据", len);
// 		httpData->dlg->AppendMsg(strMsg);
// 	}
// 	else
// 	{
// 		httpData->dlg->AppendMsg(L"PutA失败");
// 	}
// 
// 	evhttp_request_free(httpData->req);
// 	httpData->req = nullptr;
// }

void CMongooseExample_MFCDlg::OnBtnHttpPut()
{
	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	thread([&, remotePort]
		{
			CString strURI;
			strURI.Format(L"http://127.0.0.1:%d/api/putA?q=test&s=some+thing", remotePort);
			string utf8URI = UnicodeToUTF8(strURI);
			const char* uri = utf8URI.c_str();

			// 		evthread_use_windows_threads();
			// 		event_base* eventBase = event_base_new();
			// 
			// 		HttpData* httpData = new HttpData;
			// 		httpData->dlg = this;
			// 
			// 		httpData->evURI = evhttp_uri_parse(uri);
			// 		const char* host = evhttp_uri_get_host(httpData->evURI);
			// 		int port = evhttp_uri_get_port(httpData->evURI);
			// 
			// 		if (IsUseSSL())
			// 		{
			// 			// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
			// 			httpData->ssl_ctx = SSL_CTX_new(TLS_client_method());
			// 			httpData->ssl = SSL_new(httpData->ssl_ctx);
			// 			httpData->bev = bufferevent_openssl_socket_new(eventBase, -1, httpData->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
			// 			if (httpData->bev)
			// 			{
			// 				bufferevent_openssl_set_allow_dirty_shutdown(httpData->bev, 1);
			// 			}
			// 		}
			// 		else
			// 		{
			// 			httpData->bev = bufferevent_socket_new(eventBase, -1, BEV_OPT_CLOSE_ON_FREE);
			// 		}
			// 		if (httpData->bev == NULL)
			// 		{
			// 			AppendMsg(L"bev创建失败");
			// 			delete httpData;
			// 			return;
			// 		}
			// 
			// 		httpData->evConn = evhttp_connection_base_bufferevent_new(eventBase, NULL, httpData->bev, host, port);
			// 		if (httpData->evConn == NULL)
			// 		{
			// 			AppendMsg(L"evhttp_connection_base_bufferevent_new失败");
			// 			delete httpData;
			// 			return;
			// 		}
			// 
			// 		evhttp_connection_set_max_headers_size(httpData->evConn, HTTP_MAX_HEAD_SIZE);
			// 		evhttp_connection_set_max_body_size(httpData->evConn, HTTP_MAX_BODY_SIZE);
			// 		evhttp_connection_set_timeout(httpData->evConn, 1);// 设置闲置连接自动断开的超时时间(s)
			// 		
			// 		auto funReq = [httpData, eventBase]
			// 		{
			// 			auto threadID = this_thread::get_id();
			// 			evhttp_request* req = evhttp_request_new(OnHttpResponsePutA, httpData);
			// 			httpData->req = req;
			// 
			// 			// 标准Header
			// 			evhttp_add_header(req->output_headers, "Connection", "keep-alive");
			// 			evhttp_add_header(req->output_headers, "Host", "localhost");
			// 
			// 			// 自定义Header
			// 			const size_t bufSize = 1024; // 单次最大1GB（1024 * 1024 * 1024）
			// 			evhttp_add_header(req->output_headers, "bodySize", Int2Str(bufSize).c_str());
			// 
			// 			// 自定义Body数据
			// 			char* postBuf = new char[bufSize] {'A'};
			// 			evbuffer_add(req->output_buffer, postBuf, bufSize);
			// 			delete[] postBuf;
			// 
			// 			evhttp_make_request(httpData->evConn, req, EVHTTP_REQ_PUT, "/api/putA?q=test&s=some+thing");
			// 			httpData->dlg->AppendMsg(L"evhttp_make_request");
			// 		};
			// 
			// 		// 创建空白定时器，以维持eventBase
			// 		auto funcDoNothingTimer = [](evutil_socket_t fd, short event, void* arg) {};		
			// 		event* ev = event_new(eventBase, -1, EV_PERSIST, funcDoNothingTimer, nullptr);
			// 		timeval timeout = { 0, 100 };
			// 		event_add(ev, &timeout);
			// 
			// 		// 间隔发送请求，模拟长连接	
			// 		thread([funReq, ev]
			// 		{
			// 			int num = 0;
			// 			do
			// 			{
			// 				funReq();
			// 
			// 				this_thread::sleep_for(chrono::seconds(5));
			// 
			// 				num++;
			// 			} while (num < 5);
			// 			event_del(ev);
			// 			event_free(ev);
			// 		}).detach();		
			// 
			// 		event_base_dispatch(eventBase); // 阻塞			
			// 
			// 		// 先断开连接，后释放eventBase
			// 		delete httpData;
			// 		event_base_free(eventBase);
			// 		AppendMsg(L"客户端HttpPut event_base_dispatch线程 结束");
			// 
		}).detach();
}

// static void OnHttpResponseDelA(evhttp_request* req, void* arg)
// {
// 	HttpData* httpData = (HttpData*)arg;
// 
// 	if (req)
// 	{
// 		// 获取数据长度
// 		size_t len = evbuffer_get_length(req->input_buffer);
// 		if (len > 0)
// 		{
// 			// 获取数据指针
// 			unsigned char* data = evbuffer_pullup(req->input_buffer, len);
// 			char* responseStr = new char[len + 1]{ 0 };
// 			memcpy(responseStr, data, len);
// 
// 			CString strMsg;
// 			strMsg.Format(L"收到DelA接口回复：%s", UTF8ToUnicode(responseStr).c_str());
// 			httpData->dlg->AppendMsg(strMsg);
// 			delete[] responseStr;
// 
// 			// 清空数据
// 			evbuffer_drain(req->input_buffer, len);
// 			evhttp_request_free(req);
// 		}
// 	}	
// 
// 	// 主动断开与服务器连接
// 	httpData->Free();
// }

void CMongooseExample_MFCDlg::OnBtnHttpDel()
{
	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	CString strURI;
	strURI.Format(L"http://127.0.0.1:%d/api/delA?q=test&s=some+thing", remotePort);
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
	// 	evhttp_request* req = evhttp_request_new(OnHttpResponseDelA, httpData);
	// 	if (req == NULL)
	// 	{
	// 		AppendMsg(L"evhttp_request_new失败");
	// 		delete httpData;
	// 		return;
	// 	}
	// 
	// 	evhttp_make_request(httpData->evConn, req, EVHTTP_REQ_GET, "/api/delA?q=test&s=some+thing");
	// 
	// 	thread([&, eventBase, httpData]
	// 		{
	// 			event_base_dispatch(eventBase); // 阻塞
	// 			AppendMsg(L"客户端HttpGet event_base_dispatch线程 结束");
	// 
	// 			// 先断开连接，后释放eventBase
	// 			delete httpData;
	// 			event_base_free(eventBase);
	// 		}).detach();
}