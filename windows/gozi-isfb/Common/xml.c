//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: xml.c
// $Revision: 39 $
// $Date: 2013-03-19 18:02:34 +0300 (Вт, 19 мар 2013) $
// description:
//	CRM client dll. Lightweight XML parser.

#include "..\common\common.h"
#include <msxml2.h>


//
//	Creates and initializes XML interface.
//
static IXMLDOMDocument* XmlCreateInterface(VOID)
{
	IXMLDOMDocument* pXmlDoc = (IXMLDOMDocument*)ComCreateInterface((REFCLSID)&CLSID_DOMDocument30, (REFIID)&IID_IXMLDOMDocument);
	if (pXmlDoc)
	{
		CoInvoke(pXmlDoc, put_async, VARIANT_FALSE);
		CoInvoke(pXmlDoc, put_preserveWhiteSpace, VARIANT_FALSE);
		CoInvoke(pXmlDoc, put_resolveExternals, VARIANT_FALSE);
		CoInvoke(pXmlDoc, put_validateOnParse, VARIANT_TRUE);
	}
	return(pXmlDoc);
}


//
//	Opens XML interface and loads the specified XML file.
//
PVOID XmlOpenFile(
	LPWSTR		FilePath,	// path to XML file to load
	PXMLSTATUS	pXmlStatus	// structure that receives error code and line number in case of an error
	)
{
	BOOL	Ret = FALSE;
	IXMLDOMDocument* pXmlDoc;

	// Opening XML interface
	if (pXmlDoc = XmlCreateInterface())
	{
	    VARIANT_BOOL	vRet;
		VARIANT			vStr;

		VariantInit(&vStr);

		vStr.vt = VT_BSTR;
		if (vStr.bstrVal = SysAllocString(FilePath))
		{
			// Trying to load the specified XML file
			if (CoInvoke(pXmlDoc, load, vStr, &vRet) != S_OK || vRet != VARIANT_TRUE)
			{
				// An error occurred while loading the specified file
				if (pXmlStatus)
				{
					IXMLDOMParseError* iError;
					// Resolving error code and a line number
					if (CoInvoke(pXmlDoc, get_parseError, &iError) == S_OK)
					{
						CoInvoke(iError, get_errorCode, &pXmlStatus->ErrorCode);
						CoInvoke(iError, get_line, &pXmlStatus->LineNumber);

						CoInvoke(iError, Release);
					}
				}	// if (pXmlStatus)

				// Releasing XML interface
				CoInvoke(pXmlDoc, Release);
				pXmlDoc = NULL;
			}	// if (CoInvoke(pXmlDoc, load, vStr, &vRet) != S_OK || vRet != VARIANT_TRUE)
		}	// if (vStr.bstrVal = SysAllocString(FilePath))

		VariantClear(&vStr);
	}	// if (pXmlDoc = XmlCreateInterface())

	return(pXmlDoc);
}

HRESULT 
	XmlSaveFile(
		PVOID	XmlDoc,
		LPWSTR		FilePath	// path to XML file to load
		)
{
	IXMLDOMDocument* pXmlDoc = (IXMLDOMDocument*)XmlDoc;
	VARIANT			vStr;
	HRESULT hResult = S_FALSE;

	VariantInit(&vStr);

	vStr.vt = VT_BSTR;
	if (vStr.bstrVal = SysAllocString(FilePath))
	{
		hResult = CoInvoke(pXmlDoc, save, vStr );
		VariantClear(&vStr);
	}
	return hResult;
}


//
//	Closes XML file, releases interface.
//
VOID XmlCloseFile(
	PVOID	XmlDoc
	)
{
	IXMLDOMDocument* pXmlDoc = (IXMLDOMDocument*)XmlDoc;
	CoInvoke(pXmlDoc, Release);
}


//
//	Returns pointer to a XML root object with the specified name within the current document.
//
PVOID XmlGetRoot(
	PVOID	XmlDoc,		// XML document object
	LPWSTR	RootName	// name of the XML root to receive
	)
{
	IXMLDOMDocument* pXmlDoc = (IXMLDOMDocument*)XmlDoc;
	IXMLDOMElement*	pRoot = NULL;
	BOOL	Ret = FALSE;

	if (CoInvoke(pXmlDoc, get_documentElement, &pRoot) == S_OK)
	{
		BSTR CurrentName;

		if (CoInvoke(pRoot, get_nodeName, &CurrentName) == S_OK)
		{
			if (!lstrcmpiW(CurrentName, RootName))
				Ret = TRUE;
			SysFreeString(CurrentName);
		}	// if (CoInvoke(pNode, get_nodeName, CurrentNodeName) == S_OK)

		if (!Ret)
		{
			CoInvoke(pRoot, Release);
			pRoot = NULL;
		}
	}	// if (CoInvoke(pXmlDoc, get_documentElement, &pNode) == S_OK)
	return(pRoot);
}

//
//	Closes and releases the specified XML element object.
//
VOID XmlClose(
	PVOID	XmlElement
	)
{
	IXMLDOMElement*	pElement = (IXMLDOMElement*)XmlElement;
	CoInvoke(pElement, Release);
}

//
// returns single node from element
//
IXMLDOMNode* 
	XmlGetNode( 
		PVOID XmlRoot, 
		LPWSTR	ElementName	// name of the element 
		)
{
	IXMLDOMElement*	pRoot = (IXMLDOMElement*)XmlRoot;
	IXMLDOMNode*	pChild = NULL;

	if (CoInvoke(pRoot, selectSingleNode, ElementName, &pChild) != S_OK)
	{
		pChild = NULL;
	}
	return pChild;
}

IXMLDOMNode* 
	XmlGetNodeFromNode( 
		IXMLDOMNode* pNode, 
		LPWSTR	ElementName	// name of the element 
		)
{
	IXMLDOMNode*	pChild = NULL;

	if (CoInvoke(pNode, selectSingleNode, ElementName, &pChild) != S_OK)
	{
		pChild = NULL;
	}
	return pChild;
}

//
// returns first child for element
//
IXMLDOMNode* 
	XmlGetFirstChild( 
		PVOID XmlRoot
		)
{
	IXMLDOMElement*	pRoot = (IXMLDOMElement*)XmlRoot;
	IXMLDOMNode*	pChild = NULL;

	if (CoInvoke(pRoot, get_firstChild, &pChild) != S_OK)
	{
		pChild = NULL;
	}
	return pChild;
}


//
// returns single xml node text
//
LPWSTR XmlGetNodeText(
	IXMLDOMNode*	pNode
	)
{
	BSTR	Text;
	if (CoInvoke(pNode, get_text, &Text) != S_OK)
		Text = NULL;

	return(Text);
}

//
// Modifies single xml node text
//
BOOL XmlSetNodeText(
	IXMLDOMNode*	pNode,
	XMLSTR	Text
	)
{
	return (CoInvoke(pNode, put_text, Text) == S_OK);
}

//
//	Returns text content of the specified node of an XML document.
//
LPWSTR XmlGetNodeTextOfNode(
	IXMLDOMNode	*pXmlNode,	// root entry object
	LPWSTR	ElementName	// name of the element
	)
{
	LPWSTR	pText = NULL;
	IXMLDOMNode*	pChild;

	if (CoInvoke(pXmlNode, selectSingleNode, ElementName, &pChild) == S_OK)
	{
		pText = XmlGetNodeText(pChild);
		CoInvoke(pChild, Release);
	}

	return(pText);
}

//
//	Updates text content of the specified node of an XML document.
//
BOOL XmlSetNodeTextOfNode(
	IXMLDOMNode	*pXmlNode,	// root entry object
	LPWSTR	ElementName,	// name of the element
	XMLSTR	Text
	)
{
	BOOL Result = FALSE;
	IXMLDOMNode*	pChild;

	if (CoInvoke(pXmlNode, selectSingleNode, ElementName, &pChild) == S_OK)
	{
		Result = XmlSetNodeText(pChild,Text);
		CoInvoke(pChild, Release);
	}

	return Result;
}

//
//	Returns text content of the specified root entry of an XML document.
//
LPWSTR XmlGetElementText(
	PVOID	XmlRoot,	// root entry object
	LPWSTR	ElementName	// name of the element
	)
{
	LPWSTR	pText = NULL;
	IXMLDOMNode*	pChild;
	IXMLDOMElement*	pRoot = (IXMLDOMElement*)XmlRoot;

	if (CoInvoke(pRoot, selectSingleNode, ElementName, &pChild) == S_OK)
	{
		pText = XmlGetNodeText(pChild);
		CoInvoke(pChild, Release);
	}

	return(pText);
}

//
//	Frees a string allocated and returned by XML parser.
//
VOID XmlFree(
	BSTR	pString
	)
{
	SysFreeString(pString);
}