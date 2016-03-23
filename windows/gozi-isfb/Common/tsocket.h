//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.5
//	
// module: common.h
// $Revision: 372 $
// $Date: 2014-10-16 19:24:25 +0400 (Чт, 16 окт 2014) $
// description:
//  T-socket definition.

#ifdef _USE_KIP
 #include "kipapi.h"
#else
	#define	_tsocket(domain, type, protocol)							socket(domain, type, protocol)
	#define	_tclosesocket(s)											closesocket(s)
	#define _tbind(s, name, namelen)									bind(s, name, namelen)
	#define	_tlisten(s, backlog)										listen(s, backlog)
	#define	_taccept(s, addr, addrlen)									accept(s, addr, addrlen)
	#define	_tconnect(s, name, namelen)									connect(s, name, namelen)
	#define _tsend(s, buf, len, flags)									send(s, buf, len, flags)
	#define	_trecv(s, buf, len, flags)									recv(s, buf, len, flags)
	#define _tsendto(s, buf, len, flags, to, tolen)						sendto(a, buf, len, flags, to, tolen)
	#define _trecvfrom(s, buf, len, flags, from, fromlen)				recvfrom(s, buf, len, flags, from, fromlen)
	#define _tshutdown(s, how)											shutdown(s, how)	
	#define _tioctlsocket(s, cmd, argp)									ioctlsocket(s, cmd, argp)
	#define _tgetsockopt(s, level, optname, optval, optlen)				getsockopt(s, level, optname, optval, optlen)
	#define _tsetsockopt(s, level, optname, optval, optlen)				setsockopt(s, level, optname, optval, optlen)
	#define _tselect(maxfdp1, readset, writeset, exceptset, timeout)	select(maxfdp1, readset, writeset, exceptset, timeout)
	#define _tgethostbyname(name)										gethostbyname(name)
#endif
