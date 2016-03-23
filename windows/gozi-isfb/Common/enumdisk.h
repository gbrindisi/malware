/*++

Copyright (c) 1990-2000 Microsoft Corporation, All Rights Reserved

Module Name:

    enumdisk.h

Abstract:

    This file includes data declarations for the Enumdisk

Author:

    Raju Ramanathan     05/15/2000

Notes:

Revision History:


--*/

#ifndef _ENUMDISK_H_
#define _ENUMDISK_H_


//
// Command Descriptor Block constants.
//

#define CDB6GENERIC_LENGTH         6
#define CDB10GENERIC_LENGTH        10


//
// SCSI CDB operation codes
//

#define SCSIOP_TEST_UNIT_READY     0x00
#define SCSIOP_REZERO_UNIT         0x01
#define SCSIOP_REWIND              0x01
#define SCSIOP_REQUEST_BLOCK_ADDR  0x02
#define SCSIOP_REQUEST_SENSE       0x03
#define SCSIOP_FORMAT_UNIT         0x04
#define SCSIOP_READ_BLOCK_LIMITS   0x05
#define SCSIOP_REASSIGN_BLOCKS     0x07
#define SCSIOP_READ6               0x08
#define SCSIOP_RECEIVE             0x08
#define SCSIOP_WRITE6              0x0A
#define SCSIOP_PRINT               0x0A
#define SCSIOP_SEND                0x0A
#define SCSIOP_SEEK6               0x0B
#define SCSIOP_TRACK_SELECT        0x0B
#define SCSIOP_SLEW_PRINT          0x0B
#define SCSIOP_SEEK_BLOCK          0x0C
#define SCSIOP_PARTITION           0x0D
#define SCSIOP_READ_REVERSE        0x0F
#define SCSIOP_WRITE_FILEMARKS     0x10
#define SCSIOP_FLUSH_BUFFER        0x10
#define SCSIOP_SPACE               0x11
#define SCSIOP_INQUIRY             0x12
#define SCSIOP_VERIFY6             0x13
#define SCSIOP_RECOVER_BUF_DATA    0x14
#define SCSIOP_MODE_SELECT         0x15
#define SCSIOP_RESERVE_UNIT        0x16
#define SCSIOP_RELEASE_UNIT        0x17
#define SCSIOP_COPY                0x18
#define SCSIOP_ERASE               0x19
#define SCSIOP_MODE_SENSE          0x1A
#define SCSIOP_START_STOP_UNIT     0x1B
#define SCSIOP_STOP_PRINT          0x1B
#define SCSIOP_LOAD_UNLOAD         0x1B
#define SCSIOP_RECEIVE_DIAGNOSTIC  0x1C
#define SCSIOP_SEND_DIAGNOSTIC     0x1D
#define SCSIOP_MEDIUM_REMOVAL      0x1E
#define SCSIOP_READ_CAPACITY       0x25
#define SCSIOP_READ                0x28
#define SCSIOP_WRITE               0x2A
#define SCSIOP_SEEK                0x2B
#define SCSIOP_LOCATE              0x2B
#define SCSIOP_WRITE_VERIFY        0x2E
#define SCSIOP_VERIFY              0x2F
#define SCSIOP_SEARCH_DATA_HIGH    0x30
#define SCSIOP_SEARCH_DATA_EQUAL   0x31
#define SCSIOP_SEARCH_DATA_LOW     0x32
#define SCSIOP_SET_LIMITS          0x33
#define SCSIOP_READ_POSITION       0x34
#define SCSIOP_SYNCHRONIZE_CACHE   0x35
#define SCSIOP_COMPARE             0x39
#define SCSIOP_COPY_COMPARE        0x3A
#define SCSIOP_WRITE_DATA_BUFF     0x3B
#define SCSIOP_READ_DATA_BUFF      0x3C
#define SCSIOP_CHANGE_DEFINITION   0x40
#define SCSIOP_READ_SUB_CHANNEL    0x42
#define SCSIOP_READ_TOC            0x43
#define SCSIOP_READ_HEADER         0x44
#define SCSIOP_PLAY_AUDIO          0x45
#define SCSIOP_PLAY_AUDIO_MSF      0x47
#define SCSIOP_PLAY_TRACK_INDEX    0x48
#define SCSIOP_PLAY_TRACK_RELATIVE 0x49
#define SCSIOP_PAUSE_RESUME        0x4B
#define SCSIOP_LOG_SELECT          0x4C
#define SCSIOP_LOG_SENSE           0x4D


ULONG   DebugLevel = 1;
                            // 0 = Suppress All Messages
                            // 1 = Display & Fatal Error Message
                            // 2 = Warning & Debug Messages
                            // 3 = Informational Messages

//
// Bus Type
//

static char* BusType[] = {
    "UNKNOWN",  // 0x00
    "SCSI",
    "ATAPI",
    "ATA",
    "IEEE 1394",
    "SSA",
    "FIBRE",
    "USB",
    "RAID"
};

//
// SCSI Device Type
//

static char* DeviceType[] = {
    "Direct Access Device", // 0x00
    "Tape Device",          // 0x01
    "Printer Device",       // 0x02
    "Processor Device",     // 0x03
    "WORM Device",          // 0x04
    "CDROM Device",         // 0x05
    "Scanner Device",       // 0x06
    "Optical Disk",         // 0x07
    "Media Changer",        // 0x08
    "Comm. Device",         // 0x09
    "ASCIT8",               // 0x0A
    "ASCIT8",               // 0x0B
    "Array Device",         // 0x0C
    "Enclosure Device",     // 0x0D
    "RBC Device",           // 0x0E
    "Unknown Device"        // 0x0F
};

#pragma pack (push,4)
typedef enum _STORAGE_QUERY_TYPE {
    PropertyStandardQuery = 0,          // Retrieves the descriptor
    PropertyExistsQuery,                // Used to test whether the descriptor is supported
    PropertyMaskQuery,                  // Used to retrieve a mask of writeable fields in the descriptor
    PropertyQueryMaxDefined     // use to validate the value
} STORAGE_QUERY_TYPE, *PSTORAGE_QUERY_TYPE;

//
// define some initial property id's
typedef enum _STORAGE_PROPERTY_ID {
    StorageDeviceProperty = 0,
    StorageAdapterProperty,
    StorageDeviceIdProperty
} STORAGE_PROPERTY_ID, *PSTORAGE_PROPERTY_ID;

//
// Query structure - additional parameters for specific queries can follow
// the header
typedef struct _STORAGE_PROPERTY_QUERY {
    STORAGE_PROPERTY_ID PropertyId;	// ID of the property being retrieved
    STORAGE_QUERY_TYPE QueryType;	// Flags indicating the type of query being performed
    UCHAR AdditionalParameters[1]; 	// Space for additional parameters if necessary

} STORAGE_PROPERTY_QUERY, *PSTORAGE_PROPERTY_QUERY;

typedef struct _SCSI_PASS_THROUGH {
    USHORT Length;
    UCHAR ScsiStatus;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR CdbLength;
    UCHAR SenseInfoLength;
    UCHAR DataIn;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    ULONG_PTR DataBufferOffset;
    ULONG SenseInfoOffset;
    UCHAR Cdb[16];
}SCSI_PASS_THROUGH, *PSCSI_PASS_THROUGH;

typedef struct _STORAGE_ADAPTER_DESCRIPTOR {
    ULONG Version;
    ULONG Size;
    ULONG MaximumTransferLength;
    ULONG MaximumPhysicalPages;
    ULONG AlignmentMask;
    BOOLEAN AdapterUsesPio;
    BOOLEAN AdapterScansDown;
    BOOLEAN CommandQueueing;
    BOOLEAN AcceleratedTransfer;
    UCHAR BusType;
    USHORT BusMajorVersion;
    USHORT BusMinorVersion;
} STORAGE_ADAPTER_DESCRIPTOR, *PSTORAGE_ADAPTER_DESCRIPTOR;


#ifndef STORAGE_BUS_TYPE	// MINGW
typedef enum _STORAGE_BUS_TYPE {
    BusTypeUnknown = 0x00,
    BusTypeScsi,
    BusTypeAtapi,
    BusTypeAta,
    BusType1394,
    BusTypeSsa,
    BusTypeFibre,
    BusTypeUsb,
    BusTypeRAID,
    BusTypeiScsi,
    BusTypeSas,
    BusTypeSata,
    BusTypeMaxReserved = 0x7F
} STORAGE_BUS_TYPE, *PSTORAGE_BUS_TYPE;

#define CTL_CODE(t,f,m,a) (((t)<<16)|((a)<<14)|((f)<<2)|(m))

DEFINE_GUID( GUID_DEVCLASS_DISKDRIVE,           0x4d36e967L, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 );
DEFINE_GUID(GUID_DEVINTERFACE_DISK,             0x53f56307L, 0xb6bf, 0x11d0, 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b);

#define DiskClassGuid               GUID_DEVINTERFACE_DISK

#define FILE_DEVICE_CONTROLLER          0x00000004
#define FILE_DEVICE_MASS_STORAGE        0x0000002d

//
// Define the method codes for how buffers are passed for I/O and FS controls
#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3


#define FILE_ANY_ACCESS                 0
#define FILE_SPECIAL_ACCESS    (FILE_ANY_ACCESS)
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe


#endif // STORAGE_BUS_TYPE

typedef struct _STORAGE_DEVICE_DESCRIPTOR {
    ULONG Version;		// Sizeof(STORAGE_DEVICE_DESCRIPTOR)

    // Total size of the descriptor, including the space for additional
    // data and id strings
    ULONG Size;
    UCHAR DeviceType;		// The SCSI-2 device type
    UCHAR DeviceTypeModifier;	// The SCSI-2 device type modifier (if any) - this may be zero

    // Flag indicating whether the device's media (if any) is removable.  This
    // field should be ignored for media-less devices
    BOOLEAN RemovableMedia;

    // Flag indicating whether the device can support mulitple outstanding
    // commands.  The actual synchronization in this case is the responsibility
    // of the port driver.
    BOOLEAN CommandQueueing;

    // Byte offset to the zero-terminated ascii string containing the device's
    // vendor id string.  For devices with no such ID this will be zero
    ULONG VendorIdOffset;

    // Byte offset to the zero-terminated ascii string containing the device's
    // product id string.  For devices with no such ID this will be zero
    ULONG ProductIdOffset;

    // Byte offset to the zero-terminated ascii string containing the device's
    // product revision string.  For devices with no such string this will be
    // zero
    ULONG ProductRevisionOffset;

    // Byte offset to the zero-terminated ascii string containing the device's
    // serial number.  For devices with no serial number this will be zero
    ULONG SerialNumberOffset;

    // Contains the bus type (as defined above) of the device.  It should be
    // used to interpret the raw device properties at the end of this structure
    // (if any)
    STORAGE_BUS_TYPE BusType;
    ULONG RawPropertiesLength;		// The number of bytes of bus-specific data which have been appended to this descriptor
    UCHAR RawDeviceProperties[1];	// Place holder for the first byte of the bus specific property data

} STORAGE_DEVICE_DESCRIPTOR, *PSTORAGE_DEVICE_DESCRIPTOR;

#define IOCTL_STORAGE_BASE 		FILE_DEVICE_MASS_STORAGE
#define IOCTL_STORAGE_QUERY_PROPERTY   	CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCSI_BASE                 FILE_DEVICE_CONTROLLER
#define IOCTL_SCSI_PASS_THROUGH         CTL_CODE(IOCTL_SCSI_BASE, 0x0401, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define SCSI_IOCTL_DATA_OUT          0
#define SCSI_IOCTL_DATA_IN           1
#define SCSI_IOCTL_DATA_UNSPECIFIED  2

#pragma pack(pop)

typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS {
    SCSI_PASS_THROUGH Spt;
    ULONG             Filler;      // realign buffers to double word boundary
    UCHAR             SenseBuf[32];
    UCHAR             DataBuf[512];
} SCSI_PASS_THROUGH_WITH_BUFFERS, *PSCSI_PASS_THROUGH_WITH_BUFFERS;


VOID PrintError( ULONG );
VOID PrintDataBuffer( PUCHAR, ULONG );
VOID PrintStatusResults( BOOL, DWORD, PSCSI_PASS_THROUGH_WITH_BUFFERS );
VOID PrintSenseInfo( PSCSI_PASS_THROUGH_WITH_BUFFERS );
BOOL GetRegistryProperty( HDEVINFO, DWORD );
BOOL GetDeviceProperty( HDEVINFO, DWORD );
VOID DebugPrint( USHORT, PCHAR, ... );

#endif    // _ENUMDISK_H_



