//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRYPTO library project. Version 2.1
//	
// module: b64.c
// $Revision: 44 $
// $Date: 2013-03-21 13:07:14 +0300 (Чт, 21 мар 2013) $
// description: 
//	Cryptographic services provider library.
//	BASE64 algorithm implementation. String encoding and decoding.


#include <stdio.h>
#include <stdlib.h>

#define B64_DEF_LINE_SIZE   255
#define B64_MIN_LINE_SIZE    4

/*
** Translation Table as described in RFC1113
*/
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
** Translation Table to decode (created by author)
*/
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

/*
** encodeblock
**
** encode 3 8-bit binary bytes as 4 '6-bit' characters
*/
static void encodeblock( unsigned char in[3], unsigned char out[4], int len )
{
    out[0] = cb64[ in[0] >> 2 ];
    out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

/*
** encode
**
** base64 encode a stream adding padding and line breaks as per spec.
*/
void __stdcall b64encode( char* inbuf, char* outbuf, int linesize )
{
    unsigned char in[3], out[4];
    int i, len, blocksout = 0;

    while( *inbuf )
	{
        len = 0;
        for( i = 0; i < 3; i++ ) 
		{
            if (in[i] = (unsigned char)*inbuf)
			{
                len += 1;
				inbuf += 1;
			}
        }	// for( i = 0; i < 3; i++ ) 

        if( len ) 
		{
            encodeblock( in, out, len );
            for( i = 0; i < 4; i++ )
				outbuf[i] = out[i];

			outbuf += 4;
            blocksout++;
        }

        if ( blocksout >= (linesize/4) || ( *inbuf == 0) )
		{
            if( blocksout )
			{
				*(unsigned short*)outbuf = '\n\r';
				outbuf += sizeof(unsigned short);
			}
			
            blocksout = 0;
        }
    }	// while( *inbuf )

	*outbuf = 0;
}


/*
** encode
**
** base64 encode a stream adding padding and line breaks as per spec.
*/
int __stdcall B64EncodeBuffer( char* inbuf, char* outbuf, int length, int linesize )
{
    unsigned char in[3], out[4];
    int i, len, blocksout = 0;
	char* outbuf0 = outbuf;

    while( length )
	{
        len = 0;
        for( i = 0; (i < 3) && length; i++ ) 
		{
            in[i] = (unsigned char)*inbuf;
			len += 1;
			inbuf += 1;
			length -= 1;			
        }	// for( i = 0; i < 3; i++ ) 

        if( len ) 
		{
            encodeblock( in, out, len );
            for( i = 0; i < 4; i++ )
				outbuf[i] = out[i];

			outbuf += 4;
            blocksout++;
        }

        if ( blocksout >= (linesize/4) || ( length == 0) )
		{
            if( blocksout )
			{
				*(unsigned short*)outbuf = '\n\r';
				outbuf += sizeof(unsigned short);
			}
			
            blocksout = 0;
        }
    }	// while( *inbuf )

	*outbuf = 0;

	return((int)(outbuf - outbuf0));
}


/*
** decodeblock
**
** decode 4 '6-bit' characters into 3 8-bit binary bytes
*/
static void decodeblock( unsigned char in[4], unsigned char out[3] )
{   
    out[ 0 ] = (unsigned char ) (in[0] << 2 | in[1] >> 4);
    out[ 1 ] = (unsigned char ) (in[1] << 4 | in[2] >> 2);
    out[ 2 ] = (unsigned char ) (((in[2] << 6) & 0xc0) | in[3]);
}

/*
** decode
**
** decode a base64 encoded stream discarding padding, line breaks and noise
*/
void __stdcall b64decode( char* inbuf, char* outbuf )
{
    unsigned char in[4], out[3], v;
    int i, len;

    while( *inbuf ) 
	{
        for( len = 0, i = 0; i < 4 && (*inbuf); i++ ) 
		{
            v = 0;
            while( (*inbuf) && v == 0 ) 
			{
                v = (unsigned char)*inbuf;
                v = (unsigned char) ((v < 43 || v > 122) ? 0 : cd64[ v - 43 ]);
                if( v ) 
                    v = (unsigned char) ((v == '$') ? 0 : v - 61);

				if (v == 0)
					inbuf += 1;
			}

            if( *inbuf ) 
			{
                len += 1;
				inbuf += 1;

                if( v ) 
                    in[ i ] = (unsigned char) (v - 1);
                
            }
            else 
                in[i] = 0;
		}	// for( len = 0, i = 0; i < 4 && (*inbuf); i++ ) 

        if( len ) 
		{
            decodeblock( in, out );
            for( i = 0; i < len - 1; i++ ) 
				outbuf[i] = out[i];
			outbuf += (len - 1);
        }
	}	// while( *inbuf ) 

	*outbuf = 0;
}


/*
** decode
**
** decode a base64 encoded stream discarding padding, line breaks and noise
*/
int __stdcall B64DecodeBuffer(char* inbuf, char* outbuf, long length)
{
    unsigned char in[4], out[3], v;
    int i, len;
	char* outbuf0 = outbuf;

    while( *inbuf && length ) 
	{
        for( len = 0, i = 0; i < 4 && (length); i++ ) 
		{
            v = 0;
            while( (length) && v == 0 ) 
			{
                v = (unsigned char)*inbuf;
                v = (unsigned char) ((v < 43 || v > 122) ? 0 : cd64[ v - 43 ]);
                if( v ) 
                    v = (unsigned char) ((v == '$') ? 0 : v - 61);

				if (v == 0)
				{
					inbuf += 1;
					length -= 1;
				}
			}

            if(length) 
			{
                len += 1;
				inbuf += 1;
				length -= 1;

                if( v ) 
                    in[ i ] = (unsigned char) (v - 1);                
            }
            else 
                in[i] = 0;
		}	//  for( len = 0, i = 0; i < 4 && (Length); i++ ) 

        if( len ) 
		{
            decodeblock( in, out );
            for( i = 0; i < len - 1; i++ ) 
				outbuf[i] = out[i];
			outbuf += (len - 1);
        }
	}	// while( *inbuf ) 

	*outbuf = 0;
	return((int)(outbuf - outbuf0));
}
