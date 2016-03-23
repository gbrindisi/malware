//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// P2P project
//	
// module: macros.h
// $Revision: 33 $
// $Date: 2014-09-04 11:16:33 +0400 (Чт, 04 сен 2014) $
// description: 
//  common helpful macros

#ifndef _MACROS_H
#define _MACROS_H

//expression represent memory (#Pointer# points to,
//at offset of #Offset# bytes) as varibale of #Type#
#define AT_OFFSET(Type,Pointer,Offset) \
	(*((Type*)(((PUCHAR)(Pointer))+(Offset))))

//expression represent pointer to memory (#Pointer# points to,
//at offset of #Offset# bytes) as varibale of #Type#
#define P_OFFSET(Type,Pointer,Offset) \
	((Type)(((PUCHAR)(Pointer))+(Offset)))

//offset of field in struct
#define OFFSET_OF_FIELD(StructType,Field) \
	((ULONG)(&(((StructType*)NULL)->Field)))

//sizeof struct type member
#define SIZE_OF_FIELD(StructType,Field) \
	sizeof(((StructType*)NULL)->Field)

//
//  These macros are used to test, set and clear flags respectivly
//

#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif

#ifndef BooleanFlagOn
#define BooleanFlagOn(F,SF)   ((BOOLEAN)(((F) & (SF)) != 0))
#endif

#ifndef SetFlag
#define SetFlag(_F,_SF)       ((_F) |= (_SF))
#endif

#ifndef ClearFlag
#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
#endif

/*
* Rob Green, a member of the NTDEV list, provides the 
* following set of macros that'll keep you from having 
* to scratch your head and count zeros ever again.  
* Using these defintions, all you'll have to do is write:
* 
* interval.QuadPart = _RELATIVE(_SECONDS(5));
*/

#ifndef _ABSOLUTE
#define _ABSOLUTE(wait) (wait)
#endif

#ifndef _RELATIVE
#define _RELATIVE(wait) (-(wait))
#endif

#ifndef _NANOSECONDS
#define _NANOSECONDS(nanos) \
	(((signed __int64)(nanos)) / 100L)
#endif

#ifndef _MICROSECONDS
#define _MICROSECONDS(micros) \
	(((signed __int64)(micros)) * _NANOSECONDS(1000L))
#endif

#ifndef _MILLISECONDS
#define _MILLISECONDS(milli) \
	(((signed __int64)(milli)) * _MICROSECONDS(1000L))
#endif

#ifndef _SECONDS
#define _SECONDS(seconds) \
	(((signed __int64)(seconds)) * _MILLISECONDS(1000L))
#endif

#define	SEC2MS(sec)		((sec)*1000)
#define	MIN2MS(min)		SEC2MS((min)*60)
#define	HR2MS(hr)		MIN2MS((hr)*60)
#define	DAY2MS(day)		HR2MS((day)*24)
#define	SEC(sec)		(sec)
#define	MIN2S(min)		((min)*60)
#define	HR2S(hr)		MIN2S((hr)*60)
#define	DAY2S(day)		HR2S((day)*24)

// IP4 address view
#define s_saddr "%u.%u.%u.%u:%u"

#define arg_saddr(_sin) \
	((PSOCKADDR_IN)(_sin))->sin_addr.S_un.S_un_b.s_b1, \
	((PSOCKADDR_IN)(_sin))->sin_addr.S_un.S_un_b.s_b2, \
	((PSOCKADDR_IN)(_sin))->sin_addr.S_un.S_un_b.s_b3, \
	((PSOCKADDR_IN)(_sin))->sin_addr.S_un.S_un_b.s_b4, \
	htons(((PSOCKADDR_IN)(_sin))->sin_port)


#define NUMBER_OF_BLOCKS(length, alignment) (length/alignment + (length%alignment ? 1 : 0))

#define ALIGN_TO_BLOCK(length, alignment) (NUMBER_OF_BLOCKS(length,alignment)*alignment)

#endif _MACROS_H