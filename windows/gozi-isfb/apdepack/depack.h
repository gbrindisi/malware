/*
 * aPLib compression library  -  the smaller the better :)
 *
 * C depacker, header file
 *
 * Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 */

#ifndef DEPACK_H_INCLUDED
#define DEPACK_H_INCLUDED

typedef unsigned long CRC32;

#ifdef __cplusplus
extern "C" {
#endif

#ifndef APLIB_ERROR
# define APLIB_ERROR (-1)
#endif

/* function prototype */
unsigned int _stdcall aP_depack(const void *source, void *destination);

#ifdef __cplusplus
} /* extern "C" */
#endif

typedef struct _AP_FILE_HEADER
{
	unsigned long	Tag;
	unsigned long	HeaderSize;
	unsigned long	PackedSize;
	CRC32			PackedCrc;
	unsigned long	OriginalSize;
}AP_FILE_HEADER, *PAP_FILE_HEADER;


#endif /* DEPACK_H_INCLUDED */
