//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: stream.h
// $Revision: 105 $
// $Date: 2013-09-11 19:12:19 +0400 (Ср, 11 сен 2013) $
// description:
//	iStream manipulation routines.

#define CoInvoke(pObject, Method, ...)	pObject->lpVtbl->Method(pObject,  __VA_ARGS__)

__inline HRESULT StreamSeekOffset(
				LPSTREAM	pStream, 
				LONG		Ofs, 
				ULONG		Origin
				)
{
	LARGE_INTEGER Position = {Ofs, 0};
	return(CoInvoke(pStream, Seek, Position, Origin, NULL));
}

_inline ULONG StreamGetPos(
					LPSTREAM	pStream
					)
{
	LARGE_INTEGER Position = {0};
	CoInvoke(pStream, Seek, Position, STREAM_SEEK_CUR, (ULARGE_INTEGER*)&Position);
	return(Position.LowPart);
}


_inline ULONG StreamGetLength(
					LPSTREAM pStream
					)
{
	HRESULT	hResult;
	STATSTG stat;
	hResult = CoInvoke(pStream, Stat, &stat, STATFLAG_NONAME);
	ASSERT(hResult == S_OK);
	return(stat.cbSize.LowPart);
}

_inline ULONG StreamAvaliable(
	LPSTREAM pStream
	)
{
	return(StreamGetLength(pStream) - StreamGetPos(pStream));
}

_inline HRESULT StreamClear(LPSTREAM pStream)
{
	ULARGE_INTEGER qSize = {0};
	StreamSeekOffset(pStream, 0, STREAM_SEEK_SET);
	return CoInvoke(pStream, SetSize, qSize);
}

_inline HRESULT StreamCopyStream(LPSTREAM pDest, LPSTREAM pSource, ULONG nBytes)
{
	ULARGE_INTEGER qSize = {nBytes, 0};
	return CoInvoke(pSource, CopyTo, pDest, qSize, NULL, NULL);
}


#define	StreamWrite(Stream, Buffer, Length, pbWritten)	\
	CoInvoke(Stream, Write, Buffer, Length, pbWritten)

#define	StreamRead(Stream, Buffer, Length, pbRead)	\
	CoInvoke(Stream, Read, Buffer, Length, pbRead)
	

#define StreamGoto(x, y)		StreamSeekOffset(x, y, STREAM_SEEK_SET)
#define StreamGotoBegin(x)		StreamSeekOffset(x, 0, STREAM_SEEK_SET)
#define StreamGotoEnd(x)		StreamSeekOffset(x, 0, STREAM_SEEK_END)
#define	StreamRelease(x)		CoInvoke(x, Release)


_inline	VOID LineToStreamA(
	LPSTREAM	pStream,
	LPSTR		String,
	LPSTR		Delimiter
	)
{
	StreamWrite(pStream, String, lstrlenA(String) * sizeof(CHAR), NULL);
	if (Delimiter)
		StreamWrite(pStream, Delimiter, lstrlenA(Delimiter) * sizeof(CHAR), NULL);
}


_inline	VOID LineToStreamW(
	LPSTREAM	pStream,
	LPWSTR		String,
	LPWSTR		Delimiter
	)
{
	StreamWrite(pStream, String, lstrlenW(String) * sizeof(WCHAR), NULL);
	if (Delimiter)
		StreamWrite(pStream, Delimiter, lstrlenW(Delimiter) * sizeof(WCHAR), NULL);
}

#if _UNICODE
	#define	LineToStream	LineToStreamW
#else
	#define	LineToStream	LineToStreamA
#endif