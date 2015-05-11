/* Copyright (C) 2007-2008 The Android Open Source Project
**
** This software is licensed under the terms of the GNU General Public
** License version 2, as published by the Free Software Foundation, and
** may be copied, distributed, and modified under those terms.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/
#include "sim_card.h"
#include <string.h>
#include <assert.h>
#include <stdio.h>
#if defined(ENABLE_PCSC)
#if ! defined(_WIN32)
#include "pcsclite.h"
#include "wintypes.h"
#else
#define WINSCARDDATA
#define MAX_BUFFER_SIZE	264
#endif
#include "winscard.h"
#include <stdio.h>
#include <stdlib.h>
#include "reader.h"
#endif

/* set ENABLE_DYNAMIC_RECORDS to 1 to enable dynamic records
 * for now, this is an experimental feature that needs more testing
 */
#define  ENABLE_DYNAMIC_RECORDS  0

#define  A_SIM_PIN_SIZE  4
#define  A_SIM_PUK_SIZE  8

#define MAX_N_CHANNELS 20
#define H_CHANNEL_OFFSET 0x12345600

typedef struct ASimCardRec_ {
    ASimStatus  status;
    char        pin[ A_SIM_PIN_SIZE+1 ];
    char        puk[ A_SIM_PUK_SIZE+1 ];
    int         pin_retries;
    int         port;

    char        out_buff[ 1024 ];
    int         out_size;

#if defined(ENABLE_PCSC)
    SCARDCONTEXT hContext;
    SCARDHANDLE hCard;
#endif

} ASimCardRec;

static ASimCardRec  _s_card[1];

static ASimCard
sw_asimcard_create(int port)
{
    ASimCard  card    = _s_card;
    card->status      = A_SIM_STATUS_READY;
    card->pin_retries = 0;
    strncpy( card->pin, "0000", sizeof(card->pin) );
    strncpy( card->puk, "12345678", sizeof(card->puk) );
    card->port = port;
    return card;
}

static void
sw_asimcard_destroy( ASimCard  card )
{
    /* nothing really */
    card=card;
}

static __inline__ int
asimcard_ready( ASimCard  card )
{
    return card->status == A_SIM_STATUS_READY;
}

static ASimStatus
sw_asimcard_get_status( ASimCard  sim )
{
    return sim->status;
}

static void
sw_asimcard_set_status( ASimCard  sim, ASimStatus  status )
{
    sim->status = status;
}

static const char*
sw_asimcard_get_pin( ASimCard  sim )
{
    return sim->pin;
}

static const char*
sw_asimcard_get_puk( ASimCard  sim )
{
    return sim->puk;
}

static void
sw_asimcard_set_pin( ASimCard  sim, const char*  pin )
{
    strncpy( sim->pin, pin, A_SIM_PIN_SIZE );
    sim->pin_retries = 0;
}

static void
sw_asimcard_set_puk( ASimCard  sim, const char*  puk )
{
    strncpy( sim->puk, puk, A_SIM_PUK_SIZE );
    sim->pin_retries = 0;
}


static int
sw_asimcard_check_pin( ASimCard  sim, const char*  pin )
{
    if (sim->status != A_SIM_STATUS_PIN   &&
        sim->status != A_SIM_STATUS_READY )
        return 0;

    if ( !strcmp( sim->pin, pin ) ) {
        sim->status      = A_SIM_STATUS_READY;
        sim->pin_retries = 0;
        return 1;
    }

    if (sim->status != A_SIM_STATUS_READY) {
        if (++sim->pin_retries == 3)
            sim->status = A_SIM_STATUS_PUK;
    }
    return 0;
}


static int
sw_asimcard_check_puk( ASimCard  sim, const char* puk, const char*  pin )
{
    if (sim->status != A_SIM_STATUS_PUK)
        return 0;

    if ( !strcmp( sim->puk, puk ) ) {
        strncpy( sim->puk, puk, A_SIM_PUK_SIZE );
        strncpy( sim->pin, pin, A_SIM_PIN_SIZE );
        sim->status      = A_SIM_STATUS_READY;
        sim->pin_retries = 0;
        return 1;
    }

    if ( ++sim->pin_retries == 6 ) {
        sim->status = A_SIM_STATUS_ABSENT;
    }
    return 0;
}

typedef enum {
    SIM_FILE_DM = 0,
    SIM_FILE_DF,
    SIM_FILE_EF_DEDICATED,
    SIM_FILE_EF_LINEAR,
    SIM_FILE_EF_CYCLIC
} SimFileType;

typedef enum {
    SIM_FILE_READ_ONLY       = (1 << 0),
    SIM_FILE_NEED_PIN = (1 << 1),
} SimFileFlags;

/* descriptor for a known SIM File */
#define  SIM_FILE_HEAD       \
    SimFileType     type;    \
    unsigned short  id;      \
    unsigned short  flags;

typedef struct {
    SIM_FILE_HEAD
} SimFileAnyRec, *SimFileAny;

typedef struct {
    SIM_FILE_HEAD
    cbytes_t   data;
    int        length;
} SimFileEFDedicatedRec, *SimFileEFDedicated;

typedef struct {
    SIM_FILE_HEAD
    byte_t     rec_count;
    byte_t     rec_len;
    cbytes_t   records;
} SimFileEFLinearRec, *SimFileEFLinear;

typedef SimFileEFLinearRec   SimFileEFCyclicRec;
typedef SimFileEFCyclicRec*  SimFileEFCyclic;

typedef union {
    SimFileAnyRec          any;
    SimFileEFDedicatedRec  dedicated;
    SimFileEFLinearRec     linear;
    SimFileEFCyclicRec     cyclic;
} SimFileRec, *SimFile;


#if ENABLE_DYNAMIC_RECORDS
/* convert a SIM File descriptor into an ASCII string,
   assumes 'dst' is NULL or properly sized.
   return the number of chars, or -1 on error */
static int
sim_file_to_hex( SimFile  file, bytes_t  dst )
{
    SimFileType  type   = file->any.type;
    int          result = 0;

    /* see 9.2.1 in TS 51.011 */
    switch (type) {
        case SIM_FILE_EF_DEDICATED:
        case SIM_FILE_EF_LINEAR:
        case SIM_FILE_EF_CYCLIC:
            {
                if (dst) {
                    int  file_size, perm;

                    memcpy(dst, "0000", 4);  /* bytes 1-2 are RFU */
                    dst += 4;

                    /* bytes 3-4 are the file size */
                    if (type == SIM_FILE_EF_DEDICATED)
                        file_size = file->dedicated.length;
                    else
                        file_size = file->linear.rec_count * file->linear.rec_len;

                    gsm_hex_from_short( dst, file_size );
                    dst += 4;

                    /* bytes 5-6 are the file id */
                    gsm_hex_from_short( dst, file->any.id );
                    dst += 4;

                    /* byte 7 is the file type - always EF, i.e. 0x04 */
                    dst[0] = '0';
                    dst[1] = '4';
                    dst   += 2;

                    /* byte 8 is RFU, except bit 7 for cyclic files, which indicates
                       that INCREASE is allowed. Since we don't support this yet... */
                    dst[0] = '0';
                    dst[1] = '0';
                    dst   += 2;

                    /* byte 9-11 are access conditions */
                    if (file->any.flags & SIM_FILE_READ_ONLY) {
                        if (file->any.flags & SIM_FILE_NEED_PIN)
                            perm = 0x1a;
                        else
                            perm = 0x0a;
                    } else {
                        if (file->any.flags & SIM_FILE_NEED_PIN)
                            perm = 0x11;
                        else
                            perm = 0x00;
                    }
                    gsm_hex_from_byte(dst, perm);
                    memcpy( dst+2, "a0aa", 4 );
                    dst += 6;

                    /* byte 12 is file status, we don't support invalidation */
                    dst[0] = '0';
                    dst[1] = '0';
                    dst   += 2;

                    /* byte 13 is length of the following data, always 2 */
                    dst[0] = '0';
                    dst[1] = '2';
                    dst   += 2;

                    /* byte 14 is struct of EF */
                    dst[0] = '0';
                    if (type == SIM_FILE_EF_DEDICATED)
                        dst[1] = '0';
                    else if (type == SIM_FILE_EF_LINEAR)
                        dst[1] = '1';
                    else
                        dst[1] = '3';

                    /* byte 15 is lenght of record, or 0 */
                    if (type == SIM_FILE_EF_DEDICATED) {
                        dst[0] = '0';
                        dst[1] = '0';
                    } else
                        gsm_hex_from_byte( dst, file->linear.rec_len );
                }
                result = 30;
            }
            break;

        default:
            result = -1;
    }
    return result;
}


static const byte_t  _const_spn_cphs[20] = {
    0x41, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const byte_t  _const_voicemail_cphs[1] = {
    0x55
};

static const byte_t  _const_iccid[10] = {
    0x98, 0x10, 0x14, 0x30, 0x12, 0x11, 0x81, 0x15, 0x70, 0x02
};

static const byte_t  _const_cff_cphs[1] = {
    0x55
};

static SimFileEFDedicatedRec  _const_files_dedicated[] =
{
    { SIM_FILE_EF_DEDICATED, 0x6f14, SIM_FILE_READ_ONLY | SIM_FILE_NEED_PIN,
      _const_spn_cphs, sizeof(_const_spn_cphs) },

    { SIM_FILE_EF_DEDICATED, 0x6f11, SIM_FILE_NEED_PIN,
      _const_voicemail_cphs, sizeof(_const_voicemail_cphs) },

    { SIM_FILE_EF_DEDICATED, 0x2fe2, SIM_FILE_READ_ONLY,
      _const_iccid, sizeof(_const_iccid) },

    { SIM_FILE_EF_DEDICATED, 0x6f13, SIM_FILE_NEED_PIN,
      _const_cff_cphs, sizeof(_const_cff_cphs) },

    { 0, 0, 0, NULL, 0 }  /* end of list */
};
#endif /* ENABLE_DYNAMIC_RECORDS */

static const char*
sw_asimcard_io( ASimCard  sim, const char*  cmd )
{
    int  nn;
#if ENABLE_DYNAMIC_RECORDS
    int  command, id, p1, p2, p3;
#endif
    static const struct { const char*  cmd; const char*  answer; } answers[] =
    {
        { "+CRSM=192,28436,0,0,15", "+CRSM: 144,0,000000146f1404001aa0aa01020000" },
        { "+CRSM=176,28436,0,0,20", "+CRSM: 144,0,416e64726f6964ffffffffffffffffffffffffff" },

        { "+CRSM=192,28433,0,0,15", "+CRSM: 144,0,000000016f11040011a0aa01020000" },
        { "+CRSM=176,28433,0,0,1", "+CRSM: 144,0,55" },

        { "+CRSM=192,12258,0,0,15", "+CRSM: 144,0,0000000a2fe204000fa0aa01020000" },
        { "+CRSM=176,12258,0,0,10", "+CRSM: 144,0,98101430121181157002" },

        { "+CRSM=192,28435,0,0,15", "+CRSM: 144,0,000000016f13040011a0aa01020000" },
        { "+CRSM=176,28435,0,0,1",  "+CRSM: 144,0,55" },

        { "+CRSM=192,28472,0,0,15", "+CRSM: 144,0,0000000f6f3804001aa0aa01020000" },
        { "+CRSM=176,28472,0,0,15", "+CRSM: 144,0,ff30ffff3c003c03000c0000f03f00" },

        { "+CRSM=192,28617,0,0,15", "+CRSM: 144,0,000000086fc9040011a0aa01020104" },
        { "+CRSM=178,28617,1,4,4",  "+CRSM: 144,0,01000000" },

        { "+CRSM=192,28618,0,0,15", "+CRSM: 144,0,0000000a6fca040011a0aa01020105" },
        { "+CRSM=178,28618,1,4,5",  "+CRSM: 144,0,0000000000" },

        { "+CRSM=192,28589,0,0,15", "+CRSM: 144,0,000000046fad04000aa0aa01020000" },
        { "+CRSM=176,28589,0,0,4",  "+CRSM: 144,0,00000003" },

        { "+CRSM=192,28438,0,0,15", "+CRSM: 144,0,000000026f1604001aa0aa01020000" },
        { "+CRSM=176,28438,0,0,2",  "+CRSM: 144,0,0233" },

        { "+CRSM=192,28486,0,0,15", "+CRSM: 148,4" },
        { "+CRSM=192,28621,0,0,15", "+CRSM: 148,4" },

        { "+CRSM=192,28613,0,0,15", "+CRSM: 144,0,000000f06fc504000aa0aa01020118" },
        { "+CRSM=178,28613,1,4,24", "+CRSM: 144,0,43058441aa890affffffffffffffffffffffffffffffffff" },

        { "+CRSM=192,28480,0,0,15", "+CRSM: 144,0,000000806f40040011a0aa01020120" },
        { "+CRSM=178,28480,1,4,32", "+CRSM: 144,0,ffffffffffffffffffffffffffffffffffff07815155258131f5ffffffffffff" },

        { "+CRSM=192,28615,0,0,15", "+CRSM: 144,0,000000406fc7040011a0aa01020120" },
        { "+CRSM=178,28615,1,4,32", "+CRSM: 144,0,566f6963656d61696cffffffffffffffffff07915155125740f9ffffffffffff" },

        { NULL, NULL }
    };

    assert( memcmp( cmd, "+CRSM=", 6 ) == 0 );

#if ENABLE_DYNAMIC_RECORDS
    if ( sscanf(cmd, "+CRSM=%d,%d,%d,%d,%d", &command, &id, &p1, &p2, &p3) == 5 ) {
        switch (command) {
            case A_SIM_CMD_GET_RESPONSE:
                {
                    const SimFileEFDedicatedRec*  file = _const_files_dedicated;

                    assert(p1 == 0 && p2 == 0 && p3 == 15);

                    for ( ; file->id != 0; file++ ) {
                        if (file->id == id) {
                            int    count;
                            char*  out = sim->out_buff;
                            strcpy( out, "+CRSM: 144,0," );
                            out  += strlen(out);
                            count = sim_file_to_hex( (SimFile) file, out );
                            if (count < 0)
                                return "ERROR: INTERNAL SIM ERROR";
                            out[count] = 0;
                            return sim->out_buff;
                        }
                    }
                    break;
                }

            case A_SIM_CMD_READ_BINARY:
                {
                    const SimFileEFDedicatedRec*  file = _const_files_dedicated;

                    assert(p1 == 0 && p2 == 0);

                    for ( ; file->id != 0; file++ ) {
                        if (file->id == id) {
                            char*  out = sim->out_buff;

                            if (p3 > file->length)
                                return "ERROR: BINARY LENGTH IS TOO LONG";

                            strcpy( out, "+CRSM: 144,0," );
                            out  += strlen(out);
                            gsm_hex_from_bytes( out, file->data, p3 );
                            out[p3*2] = 0;
                            return sim->out_buff;
                        }
                    }
                    break;
                }

            case A_SIM_CMD_READ_RECORD:
                break;

            default:
                return "ERROR: UNSUPPORTED SIM COMMAND";
        }
    }
#endif

    if (!strcmp("+CRSM=178,28480,1,4,32", cmd)) {
        snprintf( sim->out_buff, sizeof(sim->out_buff), "+CRSM: 144,0,ffffffffffffffffffffffffffffffffffff0781515525%d1%d%df%dffffffffffff", (sim->port / 1000) % 10, (sim->port / 10) % 10, (sim->port / 100) % 10, sim->port % 10);
        return sim->out_buff;
        }

    for (nn = 0; answers[nn].cmd != NULL; nn++) {
        if ( !strcmp( answers[nn].cmd, cmd ) ) {
            return answers[nn].answer;
        }
    }
    return "ERROR: BAD COMMAND";
}

#if defined(ENABLE_PCSC)
#if defined(_WIN32)
WINSCARDDATA const SCARD_IO_REQUEST g_rgSCardT0Pci = {SCARD_PROTOCOL_T0, 8};
#endif

static SCARD_IO_REQUEST pioSendPci;
static unsigned char bRecvBuffer[MAX_BUFFER_SIZE], bSendBuffer[MAX_BUFFER_SIZE];

static int pcsc_switch_enabled = 0;
static char* pcsc_reader = NULL;

void parse_pcsc_options( const char* options )
{
    long rv;
    DWORD dwPref;
    char *mszReaders;
    ASimCard  card = _s_card;

    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &card->hContext);
    if(rv != SCARD_S_SUCCESS) {
        printf("sim_card.c: pcscd not found\n");
        return;
    }

#ifdef SCARD_AUTOALLOCATE
    dwPref = SCARD_AUTOALLOCATE;
    rv = SCardListReaders(card->hContext, NULL, (LPSTR)&mszReaders, &dwPref);
#else
    rv = SCardListReaders(card->hContext, NULL, NULL, &dwPref);
    if(rv != SCARD_S_SUCCESS) {
        printf("sim_card.c: no card reader found\n");
        return;
    }
    mszReaders = calloc(dwPref, sizeof(char));
    rv = SCardListReaders(card->hContext, NULL, mszReaders, &dwPref);
#endif

    if((rv != SCARD_S_SUCCESS) || (strlen(mszReaders) == 0)) {
        rv = SCardReleaseContext(card->hContext);

        printf("sim_card.c: no card reader found\n");
        return;
    }

    if((options != NULL) && (strlen(options) > 0)) {
        char* reader = mszReaders;
        while(strlen(reader) > 0) {
            if(!strncmp(options, reader, strlen(options))) {
                pcsc_reader = reader;
                break;
            }
            reader += strlen(reader) + 1;
        }
    }

    // fallback to first card reader in list
    if((pcsc_reader == NULL) || (strlen(pcsc_reader) == 0)) {
        pcsc_reader = mszReaders;
        while(strlen(mszReaders) > 0) {
            printf("sim_card.c: %s\n", mszReaders);
            mszReaders += strlen(mszReaders) + 1;
        }
    }
    pcsc_switch_enabled = 1;
    printf("sim_card.c: using card reader %s\n", pcsc_reader);
}

static ASimCard
pcsc_asimcard_create( int port )
{
    long rv;
    DWORD dwPref, len;
    ASimCard  card = _s_card;
    card->status = A_SIM_STATUS_ABSENT;
    card->pin_retries = 0;
    card->port = port;

    rv = SCardConnect(card->hContext, pcsc_reader, SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0, &card->hCard, &dwPref);
    if((rv != SCARD_S_SUCCESS) || (dwPref != SCARD_PROTOCOL_T0)) {

        printf("sim_card.c: failed to open card\n");
        return card;
    }

    rv = SCardReconnect(card->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0,
            SCARD_RESET_CARD, &dwPref);
    if((rv != SCARD_S_SUCCESS) || (dwPref != SCARD_PROTOCOL_T0)) {

        printf("sim_card.c: failed to reset card\n");
        return card;
    }

    pioSendPci = *SCARD_PCI_T0;

    // check for DF Telecom
    memcpy(bSendBuffer, "\xA0\xA4\x00\x00\x02\x7F\x10", 7);

    len = sizeof(bRecvBuffer);
    rv = SCardTransmit(card->hCard, &pioSendPci, bSendBuffer, 7, NULL,
            bRecvBuffer, &len);
    if((dwPref == SCARD_PROTOCOL_T1) && ((rv != SCARD_S_SUCCESS) ||
       (bRecvBuffer[len-2] != 0x90) || (bRecvBuffer[len-1] != 0x00))) {
        printf("sim_card.c: sim application not found\n");
        return card;

    }else if((dwPref != SCARD_PROTOCOL_T1) && ((rv != SCARD_S_SUCCESS) ||
             (len != 2) || (bRecvBuffer[0] != 0x9F))) {
              printf("sim_card.c: sim application not found\n");
              return card;
    }

    // identify current card status
    memcpy(bSendBuffer, "\xA0\xA4\x00\x00\x02\x6F\x40", 7);

    len = sizeof(bRecvBuffer);
    rv = SCardTransmit(card->hCard, &pioSendPci, bSendBuffer, 7, NULL,
            bRecvBuffer, &len);

    if((dwPref == SCARD_PROTOCOL_T1) && ((rv != SCARD_S_SUCCESS) ||
       (bRecvBuffer[len-2] != 0x90) || (bRecvBuffer[len-1] != 0x00))) {
        printf("sim_card.c: sim application not found\n");
        return card;

    }else if((dwPref != SCARD_PROTOCOL_T1) && ((rv != SCARD_S_SUCCESS) ||
             (len != 2) || (bRecvBuffer[0] != 0x9F))) {
              printf("sim_card.c: sim application not found\n");
              return card;
    }

    memcpy(bSendBuffer, "\xA0\xB2\x01\x04\xFC", 5);

    len = sizeof(bRecvBuffer);
    rv = SCardTransmit(card->hCard, &pioSendPci, bSendBuffer, 5, NULL,
            bRecvBuffer, &len);

    if((rv != SCARD_S_SUCCESS) || (len < 2)) {
        printf("sim_card.c: sim application not found\n");
        return card;
    }

    if((dwPref == SCARD_PROTOCOL_T1) && (bRecvBuffer[len-2] == 0x62)
       && (bRecvBuffer[len-1] == 0x82)){
        card->status = A_SIM_STATUS_READY;
    }

    if(bRecvBuffer[0] == 0x67) {
        card->status = A_SIM_STATUS_READY;
    }

    if((bRecvBuffer[0] == 0x98) && (bRecvBuffer[1] == 0x04)) {
        card->status = A_SIM_STATUS_PIN;
    }

    // TODO: TERMINAL PROFILE, should be sent by RIL
    memcpy(bSendBuffer, "\xA0\x10\x00\x00\x14\x3f\xfb\xff\xff\xff\x0f"
            "\x00\x7f\x7f\x03\xfe\x1f\x23\x05\x14\x86\x07\x00\x00\x00", 25);
    len = sizeof(bRecvBuffer);
    SCardTransmit(card->hCard, &pioSendPci, bSendBuffer, 25, NULL,
            bRecvBuffer, &len);

    // TODO: TERMINAL CAPABILITY, should be sent by RIL
    memcpy(bSendBuffer, "\x80\xAA\x00\x00\x04\xA9\x02\x81\x00", 9);

    len = sizeof(bRecvBuffer);
    SCardTransmit(card->hCard, &pioSendPci, bSendBuffer, 9, NULL,
            bRecvBuffer, &len);
    return card;
}

static void
pcsc_asimcard_destroy( ASimCard  card )
{
    long rv;

    rv = SCardDisconnect(card->hCard, SCARD_UNPOWER_CARD);
    rv = SCardReleaseContext(card->hContext);
}

static ASimStatus
pcsc_asimcard_get_status( ASimCard  sim )
{
    return sim->status;
}

static void
pcsc_asimcard_set_pin( ASimCard  sim, const char*  pin )
{
    // TODO
    sim->pin_retries = 0;
}

static int
pcsc_asimcard_check_pin( ASimCard  sim, const char*  pin )
{
    long rv;
    DWORD len;

    if (sim->status != A_SIM_STATUS_PIN   &&
        sim->status != A_SIM_STATUS_READY )
        return 0;

    memcpy(bSendBuffer,
            "\xA0\x20\x00\x01\x08\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 13);
    memcpy(&bSendBuffer[5], pin, strlen(pin));

    len = sizeof(bRecvBuffer);
    rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 13, NULL,
            bRecvBuffer, &len);
    if((rv == SCARD_S_SUCCESS) && (len == 2)) {

        if(((bRecvBuffer[0] == 0x90) && (bRecvBuffer[1] == 0x00)) || (bRecvBuffer[0] == 0x91)) {

            sim->status = A_SIM_STATUS_READY;
            sim->pin_retries = 0;
            return 1;
        }
    }

    if (sim->status != A_SIM_STATUS_READY) {
        if (++sim->pin_retries == 3)
            sim->status = A_SIM_STATUS_PUK;
    }
    return 0;
}

static int
pcsc_asimcard_check_puk( ASimCard  sim, const char* puk, const char*  pin )
{
    if (sim->status != A_SIM_STATUS_PUK)
        return 0;

    // TODO

    if ( ++sim->pin_retries == 6 ) {
        sim->status = A_SIM_STATUS_ABSENT;
    }
    return 0;
}

static void
asimcard_bytearray_to_str( char *s, unsigned char b[], int len )
{
    int i;

    for(i = 0; i < len; i++)
        sprintf(&s[i << 1], "%02x", b[i]);
}

static void
asimcard_bytearray_to_crsm( char *s, unsigned char b[], int p3 )
{
    int i;

    strcpy(s, "+CRSM: ");
    sprintf(&s[strlen(s)], "%d", b[p3]);
    strcat(s, ",");
    sprintf(&s[strlen(s)], "%d", b[p3 + 1]);

    if(p3 == 0)
        return;

    strcat(s, ",");
    for(i = 0; i < p3; i++)
        sprintf(&s[strlen(s)], "%02x", b[i]);
}

static void
asimcard_str_to_bytearray( unsigned char b[], char *s )
{
    int i;

    for(i = 0; i < (strlen(s) >> 1); i++) {
        unsigned int bb;

        sscanf(&s[i << 1], "%02x", &bb);
        b[i] = bb;
    }
}

static int
pcsc_asimcard_transcieve_apdu(
            ASimCard sim,
            unsigned char* cmdApdu,
            int cmdLength,
            unsigned char* responseApdu,
            int responseLength)
{
    memcpy(bSendBuffer, cmdApdu, cmdLength);
    DWORD len = sizeof(bRecvBuffer);
    long rc = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, cmdLength, NULL, bRecvBuffer, &len);
    if (rc != SCARD_S_SUCCESS || len < 2)
    {
        return -1;
    }

    unsigned char sw1 = bRecvBuffer[len - 2];
    unsigned char sw2 = bRecvBuffer[len - 1];
    int pos = 0;
    if (sw1 == 0x6C) {
        // Resend the same command with Le = SW2
        bSendBuffer[4] = bRecvBuffer[1];
        len = sizeof(bRecvBuffer);
        rc = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, cmdLength, NULL, bRecvBuffer, &len);
        if (rc != SCARD_S_SUCCESS || len < 2)
        {
            return -1;
        }
        sw1 = bRecvBuffer[len - 2];
        sw2 = bRecvBuffer[len - 1];
    }
    while (sw1 == 0x61 || sw2 == 0x9F)
    {
        if (len > 2)
        {
            // There is data, so save it in return buffer (except SW)
            if (pos + len > responseLength)
            {
                // Not enough space in responseApdu buffer to store data
                return -2;
            }
            memcpy(&responseApdu[pos], bRecvBuffer, len - 2);
            pos += (len - 2);
        }
        // Send a GET RESPONSE command with Le = SW2
        memcpy(&bSendBuffer[1], "\xC0\x00\x00", 3);
        bSendBuffer[4] = sw2;
        len = sizeof(bRecvBuffer);
        rc = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 5, NULL, bRecvBuffer, &len);
        if (rc != SCARD_S_SUCCESS || len < 2)
        {
            return -1;
        }
        sw1 = bRecvBuffer[len - 2];
        sw2 = bRecvBuffer[len - 1];
    }

    if (pos + len > responseLength)
    {
        return -2;
    }
    memcpy(&responseApdu[pos], bRecvBuffer, len);
    pos += len;
    return pos;
}

static const char*
pcsc_asimcard_cmd( ASimCard  sim, const char*  cmd )
{
    int clen, hChannel, iChannel;
    char command[1024];
    char c_p2[1024];

    // transmit on basic channel:
    if ( sscanf(cmd, "+CSIM=%d,\"%[0-9a-fA-F]", &clen, command) == 2 ) {
        long rv;
        DWORD len;

        if ( (strlen(command) != clen) || (((clen >> 1) << 1) != clen) )
            return "ERROR: BAD COMMAND";

        asimcard_str_to_bytearray(bSendBuffer, command);

        len = sizeof(bRecvBuffer);
        rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, clen >> 1,
                NULL, bRecvBuffer, &len);
        if((rv == SCARD_S_SUCCESS) && (len >= 2)) {
            // TODO: study why we need to control SW here.
            if(len == 2) {
                if((bRecvBuffer[0] == 0x61) || (bRecvBuffer[0] == 0x9f)) {
                    memcpy(&bSendBuffer[1], "\xc0\x00\x00", 3);
                    bSendBuffer[4] = bRecvBuffer[1];
                    len = sizeof(bRecvBuffer);
                    rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 5,
                              NULL, bRecvBuffer, &len);
                } else
                if(bRecvBuffer[0] == 0x6c) {
                    bSendBuffer[4] = bRecvBuffer[1];
                    len = sizeof(bRecvBuffer);
                    rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer,
                            clen >> 1, NULL, bRecvBuffer, &len);
                }
            }
            if((rv == SCARD_S_SUCCESS) && (len >= 2)) {
                sprintf(sim->out_buff, "+CSIM: %d,", (int)len << 1);
                asimcard_bytearray_to_str(&sim->out_buff[strlen(sim->out_buff)],
                        bRecvBuffer, len);
                return sim->out_buff;
            }
        }
        return "+CME ERROR: SIM FAILURE";
    }

    // transmit on logical channel:
    if (sscanf(cmd, "+CGLA=%d,%d,\"%[0-9a-fA-F]", &hChannel, &clen, command) == 3)
    {
        long rv;
        DWORD len;

        iChannel = hChannel - H_CHANNEL_OFFSET;
        if (iChannel <= 0  || iChannel >= MAX_N_CHANNELS)
        {
            return "+CGLA ERROR: INCORRECT PARAMETERS";
        }

        if ((strlen(command) != clen) || (((clen >> 1) << 1) != clen))
        {
            return "+CGLA ERROR: BAD COMMAND";
        }

        unsigned char cmdApdu[clen >> 1];
        unsigned char responseApdu[400];
        asimcard_str_to_bytearray(cmdApdu, command);

        if (iChannel < 4) {
            cmdApdu[0] &= 0xFC;
            cmdApdu[0] |= iChannel;
        }
        else {
            cmdApdu[0] &= 0xF0;
            cmdApdu[0] |= 0x40 | (iChannel - 4);
        }

        rv = pcsc_asimcard_transcieve_apdu(sim, cmdApdu, sizeof(cmdApdu), responseApdu, sizeof(responseApdu));
        if (rv < 0)
        {
            if (rv == -1)
            {
                return "+CGLA ERROR: SIM FAILURE";
            }
            else if (rv == -2)
            {
                return "+CGLA ERROR: NOT ENOUGH MEMORY SPACE";
            }
            else
            {
                return "+CGLA ERROR: UNEXPECTED FAILURE";
            }
        }
        sprintf(sim->out_buff, "+CGLA: %d,", (int) rv << 1);
        asimcard_bytearray_to_str(&sim->out_buff[strlen(sim->out_buff)], responseApdu, rv);
        return sim->out_buff;
    }

    // open logical channel:
    if (memcmp(cmd, "+CCHO=", 6) == 0 ) {
        long rv;
        DWORD len;

        memcpy(bSendBuffer, "\x00\x70\x00\x00\x01", 5);

        len = sizeof(bRecvBuffer);
        rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 5,
                NULL, bRecvBuffer, &len);

        if ((rv == SCARD_S_SUCCESS) && (len == 3) && (bRecvBuffer[0] > 0)) {
            iChannel = bRecvBuffer[0];

            // Check if cmd contains AID
            if (sscanf(cmd, "+CCHO=\"%[0-9a-fA-F]", command) == 1) {
                // open logical channel with AID:
                bSendBuffer[0] = (iChannel < 4) ? iChannel: 0x40 | (iChannel - 4);
                memcpy(&bSendBuffer[1], "\xa4\x04\x00", 3);
                bSendBuffer[4] = strlen(command) >> 1;
                asimcard_str_to_bytearray(&bSendBuffer[5], command);

                len = sizeof(bRecvBuffer);
                rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer,
                        bSendBuffer[4] + 5, NULL, bRecvBuffer, &len);
                if (rv == SCARD_S_SUCCESS) {
                    if ((len == 2) && (bRecvBuffer[0] == 0x61)) {
                        // Send get response
                        memcpy(&bSendBuffer[1], "\xc0\x00\x00", 3);
                        bSendBuffer[4] = bRecvBuffer[1];
                        len = sizeof(bRecvBuffer);
                        rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 5,
                                NULL, bRecvBuffer, &len);
                    } else if ((len == 2) && (bRecvBuffer[0] == 0x6C)) {
                        // Resend the command with Le = SW2
                        bSendBuffer[4] = bRecvBuffer[1];
                        len = sizeof(bRecvBuffer);
                        rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer,
                                clen >> 1, NULL, bRecvBuffer, &len);
                    }

                    // Check if select command succeeded
                    if (rv == SCARD_S_SUCCESS && len >= 2
                            && (bRecvBuffer[len-2] == 0x90
                                || bRecvBuffer[len-2] == 0x62
                                || bRecvBuffer[len-2] == 0x63)) {
                        // Resposne is "+CCHO: <channelId>,<select_resp[0]>,...,<select_resp[len-1]>
                        sprintf(sim->out_buff, "+CCHO: %d", H_CHANNEL_OFFSET + iChannel);
                        int i;
                        for (i = 0; i < len; i++) {
                            sprintf(&sim->out_buff[strlen(sim->out_buff)], ", %d", (int) bRecvBuffer[i]);
                        }
                        return sim->out_buff;
                    }
                 }
            } else {
                // open logical channel without AID:
                sprintf(sim->out_buff, "+CCHO: %d", H_CHANNEL_OFFSET + iChannel);
                return sim->out_buff;
            }

            // If something failed, close the channel
            memcpy(bSendBuffer, "\x00\x70\x80\x00\x00", 5);
            bSendBuffer[3] = iChannel;

            len = sizeof(bRecvBuffer);
            rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 5,
                    NULL, bRecvBuffer, &len);

            return "+CME ERROR: NOT FOUND";
        }
        return "+CME ERROR: MEMORY FULL";
    }

// open logical channel with p2:
    if (memcmp(cmd, "+CCHP=", 6) == 0 ) {
        long rv;
        DWORD len;

        memcpy(bSendBuffer, "\x00\x70\x00\x00\x01", 5);

        len = sizeof(bRecvBuffer);
        rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 5,
                NULL, bRecvBuffer, &len);

        if ((rv == SCARD_S_SUCCESS) && (len == 3) && (bRecvBuffer[0] > 0)) {
            iChannel = bRecvBuffer[0];

            // Check if cmd contains AID
            if (sscanf(cmd, "+CCHP=%[0-9a-fA-F],%[0-9a-fA-F]", command, c_p2) == 2) {
                // open logical channel with AID:
                bSendBuffer[0] = (iChannel < 4) ? iChannel: 0x40 | (iChannel - 4);
                memcpy(&bSendBuffer[1], "\xa4\x04", 2);
                asimcard_str_to_bytearray(&bSendBuffer[3], c_p2);
                bSendBuffer[4] = strlen(command) >> 1;
                asimcard_str_to_bytearray(&bSendBuffer[5], command);

                len = sizeof(bRecvBuffer);
                rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer,
                        bSendBuffer[4] + 5, NULL, bRecvBuffer, &len);
                if (rv == SCARD_S_SUCCESS) {
                    if ((len == 2) && (bRecvBuffer[0] == 0x61)) {
                        // Send get response
                        memcpy(&bSendBuffer[1], "\xc0\x00\x00", 3);
                        bSendBuffer[4] = bRecvBuffer[1];
                        len = sizeof(bRecvBuffer);
                        rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 5,
                                NULL, bRecvBuffer, &len);
                    } else if ((len == 2) && (bRecvBuffer[0] == 0x6C)) {
                        // Resend the command with Le = SW2
                        bSendBuffer[4] = bRecvBuffer[1];
                        len = sizeof(bRecvBuffer);
                        rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer,
                                clen >> 1, NULL, bRecvBuffer, &len);
                    }

                    // Check if select command succeeded
                    if (rv == SCARD_S_SUCCESS && len >= 2
                            && (bRecvBuffer[len-2] == 0x90
                                || bRecvBuffer[len-2] == 0x62
                                || bRecvBuffer[len-2] == 0x63)) {
                        // Resposne is "+CCHP: <channelId>,<select_resp[0]>,...,<select_resp[len-1]>
                        sprintf(sim->out_buff, "+CCHP: %d", H_CHANNEL_OFFSET + iChannel);
                        int i;
                        for (i = 0; i < len; i++) {
                            sprintf(&sim->out_buff[strlen(sim->out_buff)], ", %d", (int) bRecvBuffer[i]);
                        }
                        return sim->out_buff;
                    }
                 }
            } else {
                // open logical channel without AID:
                sprintf(sim->out_buff, "+CCHP: %d", H_CHANNEL_OFFSET + iChannel);
                return sim->out_buff;
            }

            // If something failed, close the channel
            memcpy(bSendBuffer, "\x00\x70\x80\x00\x00", 5);
            bSendBuffer[3] = iChannel;

            len = sizeof(bRecvBuffer);
            rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 5,
                    NULL, bRecvBuffer, &len);

            return "+CME ERROR: NOT FOUND";
        }
        return "+CME ERROR: MEMORY FULL";
    }

    // close logical channel:
    if ( sscanf(cmd, "+CCHC=%d", &hChannel) == 1 ) {
        long rv;
        DWORD len;

        iChannel = hChannel - H_CHANNEL_OFFSET;
        if(iChannel <= 0  || iChannel >= MAX_N_CHANNELS)
            return "+CME ERROR: INCORRECT PARAMETERS";

        memcpy(bSendBuffer, "\x00\x70\x80\x00\x00", 5);
        bSendBuffer[3] = iChannel;

        len = sizeof(bRecvBuffer);
        rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 5,
                NULL, bRecvBuffer, &len);
        if((rv == SCARD_S_SUCCESS) && (len == 2) &&
                (bRecvBuffer[0] == 0x90) && (bRecvBuffer[1] == 0x00))
            return NULL;

        return "+CME ERROR: SIM FAILURE";
    }

    // get ATR :
    if (memcmp(cmd, "+CATR", 5) == 0 ) {
        long rv;
        DWORD len,dwAtrLen;
        unsigned char pbAtr[MAX_ATR_SIZE];
        dwAtrLen = sizeof(pbAtr);
        rv = SCardGetAttrib(sim->hCard,SCARD_ATTR_ATR_STRING, pbAtr, &dwAtrLen);
        if(rv == SCARD_S_SUCCESS) {
            char auxBuf[1024];
            asimcard_bytearray_to_str(auxBuf, pbAtr,dwAtrLen);
            sprintf(sim->out_buff, "+CATR: %s", auxBuf);
            return sim->out_buff;
        }
        return "+CME ERROR: ATR NOT FOUND";
    }

    return "ERROR: BAD COMMAND";
}

static const char*
pcsc_asimcard_io( ASimCard  sim, const char*  cmd )
{
    int  command, id, p1, p2, p3;
    char pathid[12];
    long rv;
    DWORD len;

    assert( memcmp( cmd, "+CRSM=", 6 ) == 0 );
	memset( pathid, 0, sizeof(pathid));

    if (sscanf(cmd, "+CRSM=%d,%d,%d,%d,%d", &command, &id, &p1, &p2, &p3) == 5) {
        // check for pathid.
        int i = 6, j=0;
        int delimitercount = 0;
        unsigned int selects = 0;
        for( ; i < strlen(cmd); i++ ) {
            if( cmd[i] == ',' ){
                delimitercount++;
                continue;
            }
            if( delimitercount == 6 ) { // pathid comes after the 6th delimter
                pathid[j++] = cmd[i];
            }
        }

        unsigned int  str_len = strlen(pathid);
        if( (str_len % 4) != 0 ){
            return "ERROR: Invalid path";
        } else {
            selects = str_len / 4;
        }

        unsigned int path[12];

        for (i = 0; i < (str_len / 2); i++) {
            sscanf(pathid + 2*i, "%02x", &path[i]);
        }

      // SELECT DF (optional)
      if(id != 0) {
        memcpy(bSendBuffer, "\xA0\xA4\x00\x00\x02\x7F\x20", 7);
        if((id == 0x6F3A) || (id == 0x6F3B) || (id == 0x6F3C) ||
           (id == 0x6F3D) || (id == 0x6F40) || (id == 0x6F42) ||
           (id == 0x6F43) || (id == 0x6F44) || (id == 0x6F47) ||
           (id == 0x6F49) || (id == 0x6F4A) || (id == 0x6F4B) ||
           (id == 0x6F4C) || (id == 0x6F4D) || (id == 0x6F4E)) {

            path[0] = 0x7F;
            path[1] = 0x10;
            selects = 1;
        } else
        if((id == 0x2FE2) || (id == 0x2F05) || (id == 0x2F00)) {

            path[0] = 0x3F;
            path[1] = 0x00;
            selects = 1;
        }

        len = sizeof(bRecvBuffer);
        for( i = 0; i < selects; i++ ) {
            bSendBuffer[5] = path[2*i];
            bSendBuffer[6] = path[2*i+1];
            rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 7,
                    NULL, bRecvBuffer, &len);
            if((rv != SCARD_S_SUCCESS) || (len != 2) || (bRecvBuffer[0] != 0x9F))
                return "ERROR: SELECT DF FAILED";
        }
      }

      switch (command) {
        case A_SIM_CMD_GET_RESPONSE:
          {
            memcpy(bSendBuffer, "\xA0\xA4\x00\x00\x02\xFF\xFF", 7);
            bSendBuffer[5] = id >> 8;
            bSendBuffer[6] = id & 0xff;

            len = sizeof(bRecvBuffer);
            rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 7,
                    NULL, bRecvBuffer, &len);
            if((rv == SCARD_S_SUCCESS) && (len == 2) &&
                    (bRecvBuffer[0] == 0x9F)) {

              memcpy(bSendBuffer, "\xA0\xC0\x00\x00\x0F", 5);

              len = sizeof(bRecvBuffer);
              rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 5,
                      NULL, bRecvBuffer, &len);
              if((rv == SCARD_S_SUCCESS) && (len >= 2)) {

                asimcard_bytearray_to_crsm(sim->out_buff, bRecvBuffer, len-2);
                return sim->out_buff;
              }
            }

            return "ERROR: INTERNAL SIM ERROR";
            break;
          }

        case A_SIM_CMD_READ_BINARY:
          {
            // force EF(AD) content to match settings of MNO (len(MNC) = 3)
            if((id == 0x6FAD) && (p3 == 4))
                return "+CRSM: 144,0,00000003";

            memcpy(bSendBuffer, "\xA0\xA4\x00\x00\x02\xFF\xFF", 7);
            bSendBuffer[5] = id >> 8;
            bSendBuffer[6] = id & 0xff;

            len = sizeof(bRecvBuffer);
            rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 7,
                    NULL, bRecvBuffer, &len);
            if((rv == SCARD_S_SUCCESS) && (len == 2) &&
                    (bRecvBuffer[0] == 0x9F)) {

              memcpy(bSendBuffer, "\xA0\xB0\x00\x00\xFF", 5);
              bSendBuffer[3] = p2 & 0xff;
              bSendBuffer[4] = p3 & 0xff;

              len = sizeof(bRecvBuffer);
              rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 5,
                      NULL, bRecvBuffer, &len);
              if((rv == SCARD_S_SUCCESS) && (len >= 2)) {

                asimcard_bytearray_to_crsm(sim->out_buff, bRecvBuffer, len-2);
                return sim->out_buff;
              }
            }

            return "ERROR: INTERNAL SIM ERROR";
            break;
          }

        case A_SIM_CMD_READ_RECORD:
          {
            memcpy(bSendBuffer, "\xA0\xA4\x00\x00\x02\xFF\xFF", 7);
            bSendBuffer[5] = id >> 8;
            bSendBuffer[6] = id & 0xff;

            len = sizeof(bRecvBuffer);
            rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 7,
                    NULL, bRecvBuffer, &len);
            if((rv == SCARD_S_SUCCESS) && (len == 2) &&
                    (bRecvBuffer[0] == 0x9F)) {

              memcpy(bSendBuffer, "\xA0\xB2\xFF\xFF\xFF", 5);
              bSendBuffer[2] = p1 & 0xff;
              bSendBuffer[3] = p2 & 0xff;
              bSendBuffer[4] = p3 & 0xff;

              len = sizeof(bRecvBuffer);
              rv = SCardTransmit(sim->hCard, &pioSendPci, bSendBuffer, 5,
                      NULL, bRecvBuffer, &len);
              if((rv == SCARD_S_SUCCESS) && (len >= 2)) {

                asimcard_bytearray_to_crsm(sim->out_buff, bRecvBuffer, len-2);
                return sim->out_buff;
              }
            }

            return "ERROR: INTERNAL SIM ERROR";
            break;
          }

        default:
          return "ERROR: UNSUPPORTED SIM COMMAND";
      }
    }
    return "ERROR: BAD COMMAND";
}

#endif /* ENABLE_PCSC */

/* wrapper functions */

ASimCard
asimcard_create( int port )
{
#if defined(ENABLE_PCSC)
    if (pcsc_switch_enabled)
        return pcsc_asimcard_create(port);
#endif
    return sw_asimcard_create(port);
}

void
asimcard_destroy( ASimCard  card )
{
#if defined(ENABLE_PCSC)
    if (pcsc_switch_enabled)
        return pcsc_asimcard_destroy(card);
#endif
    return sw_asimcard_destroy(card);
}

ASimStatus
asimcard_get_status( ASimCard  sim )
{
#if defined(ENABLE_PCSC)
    if (pcsc_switch_enabled)
        return pcsc_asimcard_get_status(sim);
#endif
    return sw_asimcard_get_status(sim);
}

void
asimcard_set_pin( ASimCard  sim, const char*  pin )
{
#if defined(ENABLE_PCSC)
    if (pcsc_switch_enabled)
        return pcsc_asimcard_set_pin(sim, pin);
#endif
    return sw_asimcard_set_pin(sim, pin);
}

int
asimcard_check_pin( ASimCard  sim, const char*  pin )
{
#if defined(ENABLE_PCSC)
    if (pcsc_switch_enabled)
        return pcsc_asimcard_check_pin(sim, pin);
#endif
    return sw_asimcard_check_pin(sim, pin);
}

int
asimcard_check_puk( ASimCard  sim, const char* puk, const char*  pin )
{
#if defined(ENABLE_PCSC)
    if (pcsc_switch_enabled)
        return pcsc_asimcard_check_puk(sim, puk, pin);
#endif
    return sw_asimcard_check_puk(sim, puk, pin);
}

const char*
asimcard_io( ASimCard  sim, const char*  cmd )
{
#if defined(ENABLE_PCSC)
    if (pcsc_switch_enabled)
        return pcsc_asimcard_io(sim, cmd);
#endif
    return sw_asimcard_io(sim, cmd);
}

const char*
asimcard_cmd( ASimCard sim, const char* cmd )
{
#if defined(ENABLE_PCSC)
    if (pcsc_switch_enabled)
        return pcsc_asimcard_cmd(sim, cmd);
#endif
    return "ERROR: UNSUPPORTED COMMAND";
}

