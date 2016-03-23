//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: xml.h
// $Revision: 39 $
// $Date: 2013-03-19 18:02:34 +0300 (Вт, 19 мар 2013) $
// description:
//	CRM client dll. Lightweight XML parser.


// XML string allocated by XML parser.
// Must be freed by XmlFree() function only.
#define	XMLSTR	LPWSTR


typedef struct _XMLSTATUS
{
	ULONG	ErrorCode;
	ULONG	LineNumber;
} XMLSTATUS, *PXMLSTATUS;


//
//	Opens XML interface and loads the specified XML file.
//
PVOID XmlOpenFile(
	LPWSTR		FilePath,	// path to XML file to load
	PXMLSTATUS	pXmlStatus	// structure that receives error code and line number in case of an error
	);

HRESULT 
	XmlSaveFile(
		PVOID	XmlDoc,
		LPWSTR		FilePath	// path to XML file to load
		);
//
//	Closes XML file, releases interface.
//
VOID XmlCloseFile(
	PVOID	XmlDoc
	);


//
//	Returns pointer to a XML root object with the specified name within the current document.
//
PVOID XmlGetRoot(
	PVOID	XmlDoc,		// XML document object
	LPWSTR	RootName	// name of the XML root to receive
	);


//
//	Closes and releases the specified XML element object.
//
VOID XmlClose(
	PVOID	XmlElement
	);

IXMLDOMNode*
	XmlGetNode( 
		PVOID XmlRoot, 
		LPWSTR	ElementName	// name of the element 
		);

IXMLDOMNode* 
	XmlGetNodeFromNode( 
		IXMLDOMNode* pNode, 
		LPWSTR	ElementName	// name of the element 
		);

IXMLDOMNode* 
	XmlGetFirstChild( 
		PVOID XmlRoot
		);

//
//	Returns text content of the specified root entry of an XML document.
//
XMLSTR XmlGetElementText(
	PVOID	XmlRoot,	// root entry object
	LPWSTR	ElementName	// name of the element
	);

LPWSTR XmlGetNodeText(
	IXMLDOMNode*	pNode
	);

BOOL XmlSetNodeText(
	IXMLDOMNode*	pNode,
	XMLSTR	Text
	);

LPWSTR XmlGetNodeTextOfNode(
	IXMLDOMNode	*pXmlNode,	// root entry object
	LPWSTR	ElementName	// name of the element
	);

BOOL XmlSetNodeTextOfNode(
	IXMLDOMNode	*pXmlNode,	// root entry object
	LPWSTR	ElementName,	// name of the element
	XMLSTR	Text
	);

//
//	Frees a string allocated and returned by XML parser.
//
VOID XmlFree(
	XMLSTR	pString
	);

#define XmlRelease(Object) CoInvoke(Object, Release)