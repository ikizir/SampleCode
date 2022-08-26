/***************************************************************************
 * B.									   *
 *   Copyright (C) 2005 by Ismail Kizir                                    *
 ***************************************************************************/
#include "Config.h"
#include "httpClient.h"
#include "portable_endian.h"
#include "mystrings.h"
#include "IOBuffers.h"
#include "Multiplexer.h"
#include "mytemplate.h"
#include "httpCommon.h"
#include "KVList.h"
//#include <openssl/sha.h>
#include "MyAtomic.h"
#include "MyHashZStr.h"
#include "HohhaX25519.h"
#include "crypto_kem.h"
#include "CustomEnc.h"
#include "CharSets.h"
// If you want to use
#if defined(USE_HUGE_LIBBASE64_LIBRARY)
#include "libbase64.h"
#else
#include "HohhaXor.h"
#endif

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mymisc.h>
#include <mystrings.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include<netinet/in.h>

#include <ctype.h>
#include <sys/mman.h>
#include <mime.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>

//#define DEBUG
//#define HDEBUG

// Some variables are defined in httpCommon.c
//#define MAX_NUM_REQUEST_HEADERS 24
//#define MAX_NUM_RESPONSE_HEADERS 24
#define MAX_NUM_UPLOADED_FILES 32
#define MAX_NUM_GPC_VARS 256
//#define MAX_GPC_VAR_NAME_LEN 63
#define MAX_POST_SIZE 1024*1024
#define DEFAULT_GPC_VAR_VALUE_INITIAL_BUFSIZE 4096
#define MAX_GPC_VAR_VALUE_LEN 4096

#define cstJUST_INITIALIZED 0
#define cstRESOLVING_DNS 1
#define cstCONNECTING 2
#define cstREADY_FOR_QUERY 3
#define cstHTTP_REQUEST_SEND_WAITING_FOR_REPLY 4
#define cstPARSING_HTTP_VERSION 5
#define cstPARSING_HTTP_STATUS_CODE 6
#define cstPARSING_HTTP_STATUS_STRING 7
#define cstPARSING_HEADER_VAR_NAME 8
#define cstPARSING_HEADER_VAR_VALUE 9
#define cstPARSING_COOKIE_NAME 10
#define cstPARSING_COOKIE_VALUE 11
#define cstPARSING_COOKIE_PROPERTY_NAME 12
#define cstPARSING_COOKIE_PROPERTY_VALUE 13
#define cstPARSING_POST_VAR_NAME 14
#define cstPARSING_POST_VAR_VALUE 15
#define cstPARSING_FIRST_MULTIPART_BOUNDARY 16
#define cstPARSING_MULTIPART_HEADERS 17 // Content-disposition: blah blah
#define cstPARSING_MULTIPART_BODY 18

static TBool chttpNewDataIsAvailable (TIOBuf *io, TMemInputBuffer *mib);

TSocketProfileTCP HTTP_CLIENT_DEFAULT_SOCKET_PROFILE = {
  .ExtraSocketProfileData = NULL,
  .TimeoutBeforeLogin = 5000,
  .SocketKernelSendBufSize = 0,
  .SocketKernelRecvBufSize = 0,
  .CommProtocol = protoRaw,
  .RequiresLogin = IOB_LOGIN_NOT_REQUIRED,
  .FreeThisStructure = 1, // By default, it must always be created dynamically
  .fncGetHohhaEncryptionKeyWebSocket = NULL,
  .fncOnFlushComplete = NULL,
  .fncIOBufNewRawDataIsAvailable = chttpNewDataIsAvailable,
  .fncOnSocketIsReadyToWrite = NULL,
  .fncOnClose = NULL,
  .fncOutputObjectStats = NULL,
  .fncOnOutgoingConnectSuccess = NULL,
  .fncIOBufPostInit = NULL,
  .ConnectTimeout = 60000,
  .IndividualAddrPortConnectTimeout = 30000,
  .Timeout = 15000,
  .InitialOutputBufSize = 4000,
  .NetServiceType = NET_SERVICE_HTTP,
  .CompressionType = IOB_COMP_DEFLATE, // It will be automatically negotiated if it's not IOB_COMP_NONE!
  .IncomingConn = 0,
  .isSSL = 0 // This is 0 by default. ocConnect will set it to 1 automatically
};

TSocketProfileTCP *chttpGetDefaultSockProfile(void)
{
  return &HTTP_CLIENT_DEFAULT_SOCKET_PROFILE;
}

static inline void chttpSetParserError(TCHttp *s, uint16_t E)
{
  s->ParserError = E;
}
#if !defined(DEBUG) 
static 
#endif
void chttpInternalfncOnClose(TIOBuf *io, uint32_t Reason)
{
  TCHttp *CHTTP = (TCHttp *)io->ExtraData.p;
  if (CHTTP)
  {
//  TMultiplexer *mpx = CAST(io->SocketProfile->Multiplexer, TMultiplexer *);
    //DBGPRINT(DBGLVL_DBG, "\n\n\n!!!!! chttpOnConnectionLost called. REASON: %u MpxCurCyleNo: %llu !!!!!\n\n\n", (unsigned)Reason, (unsigned long long int)mpxGetCycleNo(chttpGetMultiplexer(CHTTP)));
    if (CHTTP->fncOnRequestCompleted)
    {
      chttpSetParserError(CHTTP, HTTP_PARSER_ERROR_NOT_CONNECTED);
      CHTTP->fncOnRequestCompleted(CHTTP);
    }
    chttpDestroyAndFree(CHTTP);
  }
}

// Private functions
static int32_t chttpGetChar(TCHttp *s);
static int32_t chttpGetRawChar(TCHttp *s)
{
  if (mibThereIsDataToRead(s->LastInputChunk))
  {
    s->LastCharRead = s->LastInputChunk->DataBuf[s->LastInputChunk->ReadingPos++];
    return s->LastCharRead;
  }
  return IOB_END_OF_BUFFER;
}

/**
 * chttpCreateOutgoingConn creates a new TOutgoingConn structure with an appropriate socket profile to be used as TCHttp's outgoing connection object
 * @param mpx Multiplexer
 * @param isSecure 1 if it will be an SSL(https or wss) connection; 0 if not! USE ONLY 1 or 0 values! It's not a boolean
 * @param TCBFncParam ExtraData is the parameters to pass to OutgoingConn object to be created
 * @return new TOutgoingConn object pointer
 */
TOutgoingConn *chttpCreateOutgoingConn(TMultiplexer *mpx, uint8_t isSecure, TCBFncParam ExtraData)
{
  assert(isSecure <= 1);
  TOutgoingConn *OConn = ocInitNew(
    mpx,
    &HTTP_CLIENT_DEFAULT_SOCKET_PROFILE,
    ExtraData);
  return OConn;
}

/**
 * chttpInit initializes a client http object with an already connected io
 * @param s Previously allocated TCHttp pointer
 * @param io Already connected TIOBuf pointer
 * @param Host Host: xxx header to be sent with http requests
 * @return 
 */
int32_t chttpInit(TCHttp *s, TIOBuf *io, const char *Host, TCBFncParam ExtraData)
{ // Called as a TfncIOBufPostInit function after IOBufStruct init. The caller will be called by inheriting objects
  A_memset(s, 0, sizeof(TCHttp));
  // We set TCHttp's io property to io object
#if defined(MULTIPLE_CONCURRENT_MULTIPLEXERS)
  s->mpx = iobGetMultiplexer(io);
#endif

  s->ExtraData = ExtraData;
  s->io = io; //ocInitNew(mpx, &HTTP_CLIENT_DEFAULT_SOCKET_PROFILE, s);
  s->RequestContentType = MIME_APPLICATION_X_WWW_FORM_URLENCODED;
  iobIncRefCounter(io);
  io->ExtraData.p = s;
  io->SocketProfile->fncOnClose = chttpInternalfncOnClose;
  io->SocketProfile->fncIOBufNewRawDataIsAvailable = chttpNewDataIsAvailable;
  InitChunk(&s->ChunkInfo, 4000);
  uint32_t HostLen = (uint32_t)strlen(Host);
  if (HostLen > LEN_CONST("http://"))
  {
    if (memcmp(Host, "http://", LEN_CONST("http://")) == 0)
      s->Host = ChunkStrDupLen(&s->ChunkInfo, Host + LEN_CONST("http://"), HostLen - LEN_CONST("http://"));
    else if (memcmp(Host, "https://", LEN_CONST("https://")) == 0)
      s->Host = ChunkStrDupLen(&s->ChunkInfo, Host + LEN_CONST("https://"), HostLen - LEN_CONST("https://"));
    else s->Host = ChunkStrDupLen(&s->ChunkInfo, Host, HostLen);
  } else s->Host = ChunkStrDupLen(&s->ChunkInfo, Host, HostLen);

  kvInit(&s->RequestGetOrPOSTVars); 
  kvInit(&s->RequestHeaders);
  kvInit(&s->ResponseHeaders);
  kvInit(&s->ResponseCookies);
  s->LastElementData = smbInitNew(DEFAULT_GPC_VAR_VALUE_INITIAL_BUFSIZE);
  if (!s->LastElementData) 
    return -1;
  //chttpSetState(s, stPARSING_METHOD); 
  return 1; // Returns a positive value on success
}

/**
 * chttpInitNew Allocates a new TCHttp structure from io's underlying memory manager
 *   and initializes a client http object with an already connected io
 * @param io Already connected TIOBuf pointer
 * @param Host Host: xxx header to be sent with http requests
 * @return 
 */
TCHttp *chttpInitNew(TIOBuf *io, const char *Host, TCBFncParam ExtraData)
{
  TCHttp *chttp;
  
  chttp = (TCHttp *)mAlloc(sizeof(TCHttp));
  if (!chttp)
    return NULL;
  if (chttpInit(chttp, io, Host, ExtraData) < 0)
  {
    mFree(chttp);
    return NULL;
  }
  chttp->FreeThisStructure = 1;
  return chttp;
}

void chttpAddRequestHeader(TCHttp *s,const char *K, const uint32_t MallocForKey, const char *V, const uint32_t MallocForValue)
{
  TKeyValue *KV = (TKeyValue *)chttpMAlloc(s, sizeof(TKeyValue));
  
  KV->KeyStrLen = (uint32_t)strlen(K);
  KV->ValueStrLen = (uint32_t)strlen(V);
  KV->KeyAsStrPtr = (MallocForKey ? chttpStrDupLen(s, K, KV->KeyStrLen) : K);
  KV->ValueAsStrPtr = (MallocForValue ? chttpStrDupLen(s, V, KV->ValueStrLen) : V);
  kvGetOrSetWithStrKey(&s->RequestHeaders, KV);
}
/**
 * chttpAddAuthenticationCredentials adds basic authentication credentials to request 
 *   as described in rfc2617: https://tools.ietf.org/html/rfc2617
 * @param s TCHttp *
 * @param UserName const char *
 * @param Password 
 * @return TRUE if Authorization header successfully added. FALSE if parameters are invalid
 */ 
TBool chttpAddAuthenticationCredentials(TCHttp *s, const char *UserName, const char *Password)
{
  char S[192], S1[512];
  if (UserName && Password)
  {
    size_t UserNameLen = strlen(UserName), PasswordLen = strlen(Password);
    if (likely(UserNameLen && PasswordLen && UserNameLen <= 80 && PasswordLen <= 80))
    {
      memcpy(S, UserName, UserNameLen);
      S[UserNameLen] = ':';
      memcpy(S + UserNameLen + 1, Password, PasswordLen+1);
      
      memcpy(S1, "Basic ", 6);
      size_t EncodedStrLen;
      // If you want to use 
      #if defined(USE_HUGE_LIBBASE64_LIBRARY)
      int Flags = 0; // BASE64_FORCE_SSE42
      base64_encode(S, (UserNameLen + PasswordLen +1), S1 + 6, &EncodedStrLen, Flags);
      #else
      base64_encodestate Base64EncodeState;
      base64_init_encodestate(&Base64EncodeState);
      EncodedStrLen = base64_encode_block(S, (UserNameLen + PasswordLen +1), S1 + 6, &Base64EncodeState);
      #endif
      // Base64_encode doesn't put a zero pad(\0) at the end of string. We must do it
      S1[6 + EncodedStrLen] = '\0';
#if defined(HCDEBUG)
      //DBGPRINT(DBGLVL_DBG,  "http auth credentials to send: %s Encoded base64 len: %llu\n", S1, (unsigned long long int)EncodedStrLen);
#endif
      chttpAddRequestHeader(s, "Authorization", FALSE, S1, TRUE);
      return TRUE;
    }
  }
  return FALSE;
}
void chttpAddResponseHeaderInt64 (TCHttp *s, const char *K, uint32_t MAllocForKey, int64_t Num)
{
  char NumBuf[48];
  
  sprintf(NumBuf,"%lld", (long long int)Num);
  chttpAddResponseHeader (s, K, MAllocForKey, NumBuf, TRUE);
}

void chttpAddResponseHeader(TCHttp *s, const char *K, uint32_t MallocForKey, const char *V, uint32_t MallocForValue)
{
  TKeyValue *KV = kvGetWithStrKey(&s->ResponseHeaders, K);
  
  if (KV == NULL)
  { // No header with same key previously received
    KV = (TKeyValue *)chttpMAlloc(s, sizeof(TKeyValue));
    KV->KeyStrLen = (unsigned)strlen(K);
    KV->ValueStrLen = (unsigned)strlen(V);
    KV->KeyAsStrPtr = (MallocForKey ? chttpStrDup(s, K) : K);
    KV->ValueAsStrPtr = (MallocForValue ? chttpStrDup(s, V) : V);
    kvGetOrSetWithStrKey(&s->ResponseHeaders, KV);
  }
  else {
    // Already found. We add comma and the value
    char *ss = chttpMAlloc(s, strlen(V) + KV->ValueStrLen + 2);
    KV->ValueStrLen = (uint32_t)sprintf(ss, "%s,%s", KV->ValueAsStrPtr, V);
    KV->ValueAsStrPtr = ss;
  }
}
void chttpAddRequestGetOrPOSTVar(TCHttp *s,const char *K, uint32_t MallocForKey, const char *V, uint32_t MallocForValue)
{
  TKeyValue *KV = (TKeyValue *)chttpMAlloc(s, sizeof(TKeyValue));
  
  KV->KeyStrLen = (uint32_t)strlen(K);
  KV->ValueStrLen = (uint32_t)strlen(V);
  KV->KeyAsStrPtr = (MallocForKey ? chttpStrDupLen(s, K, KV->KeyStrLen) : K);
  KV->ValueAsStrPtr = (MallocForValue ? chttpStrDupLen(s, V, KV->ValueStrLen) : V);
  kvGetOrSetWithStrKey(&s->RequestGetOrPOSTVars, KV);
}
void chttpAddRequestGetOrPOSTVarBin(TCHttp *s,const char *K, const uint32_t MallocForKey, const char *V, const uint32_t ValueLen, const uint32_t MallocForValue)
{
  TKeyValue *KV = (TKeyValue *)chttpMAlloc(s, sizeof(TKeyValue));
  
  KV->KeyStrLen = (unsigned)strlen(K);
  KV->ValueStrLen = ValueLen;
  KV->KeyAsStrPtr = (MallocForKey ? chttpStrDupLen(s, K, KV->KeyStrLen) : K);
  if (MallocForValue)
  {
    KV->ValueAsStrPtr = (const char *)chttpMAlloc(s, ValueLen);
    memcpy((void *)KV->ValueAsStrPtr, V, ValueLen);
  } else KV->ValueAsStrPtr = V;
  KV->ValueAsStrPtr = (MallocForValue ? chttpStrDupLen(s, V, ValueLen) : V);
  kvGetOrSetWithStrKey(&s->RequestGetOrPOSTVars, KV);
}

void chttpAddRequestGetOrPOSTVarInt64 (TCHttp *s, const char *K, uint32_t MAllocForKey, int64_t Num)
{
  char NumBuf[48];
  TKeyValue *KV = (TKeyValue *)chttpMAlloc(s, sizeof(TKeyValue));
  
  KV->KeyStrLen = (unsigned)strlen(K);
  KV->ValueStrLen = (unsigned)Int64ToStr(Num, NumBuf);
  KV->KeyAsStrPtr = (MAllocForKey ? chttpStrDupLen(s, K, KV->KeyStrLen) : K);
  KV->ValueAsStrPtr = chttpStrDupLen(s, NumBuf, KV->ValueStrLen);
  kvGetOrSetWithStrKey(&s->RequestGetOrPOSTVars, KV);
}
void chttpAddRequestGetOrPOSTVarUInt64 (TCHttp *s, const char *K, uint32_t MAllocForKey, int64_t Num)
{
  char NumBuf[48];
  TKeyValue *KV = (TKeyValue *)chttpMAlloc(s, sizeof(TKeyValue));
  
  KV->KeyStrLen = (unsigned)strlen(K);
  KV->ValueStrLen = UInt64ToStr(Num, NumBuf);
  KV->KeyAsStrPtr = (MAllocForKey ? chttpStrDupLen(s, K, KV->KeyStrLen) : K);
  KV->ValueAsStrPtr = chttpStrDupLen(s, NumBuf, KV->ValueStrLen);
  kvGetOrSetWithStrKey(&s->RequestGetOrPOSTVars, KV);
}
/**
 * chttpAddRequestGetOrPOSTVarBase64 adds a request var as a base64 encoded string
 * @param s TCHttp *
 * @param K Key name
 * @param MallocForKey TRUE if memory will be allocated
 * @param V Value buffer pointer
 * @param VLen Length of value buffer.
 */
void chttpAddRequestGetOrPOSTVarBase64(TCHttp *s, const char *K, uint32_t MallocForKey, const void *V, const uint32_t VLen)
{
  TKeyValue *KV = (TKeyValue *)chttpMAlloc(s, sizeof(TKeyValue));
  KV->KeyStrLen = (unsigned)strlen(K);
  KV->KeyAsStrPtr = (MallocForKey ? chttpStrDupLen(s, K, KV->KeyStrLen) : K);
  
  size_t N, ReqSpc = BASE64_ENCODED_LEN(VLen) + 1;
  
  KV->ValueAsStrPtr = chttpMAlloc(s, ReqSpc);
  base64_encode((const char *)V, VLen, (char *)KV->ValueAsStrPtr, &N, 0);
  *((char *)KV->ValueAsStrPtr + N) = '\0';
  KV->ValueStrLen = N;
  kvGetOrSetWithStrKey(&s->RequestGetOrPOSTVars, KV);
}

#if !defined(DEBUG) 
static 
#endif
int32_t chttpGetChar(TCHttp *s)
{
  int32_t PrevChar, CurChar;
  char *tmpptr;
  
lblGetCharEntry:  
  PrevChar = chttpGetLastRawCharRead(s);
  
  if (s->ChunkReadState == CRS_READING_CHUNK_HEADER)
  {
    while ((CurChar = chttpGetRawChar(s)) != IOB_END_OF_BUFFER)
    {
      if (CurChar == '\n' && PrevChar == '\r')
      {
        s->CurrentChunkLen = strtol((const char *)smbGetBuf(s->ChunkHeaderAndTrailerData), &tmpptr, 16);
        s->CurrentChunkNumRead = 0;
        s->ChunkReadState = CRS_READING_CHUNK_BODY;
        smbClear(s->ChunkHeaderAndTrailerData);
        if (s->CurrentChunkLen == 0)
        {
          s->ConsumedAllData = 1;
          return IOB_END_OF_BUFFER;
        }
        break;
      } else smbSendChar(s->ChunkHeaderAndTrailerData, CurChar);
      PrevChar = CurChar;
    }
    if (CurChar == IOB_END_OF_BUFFER)
      return IOB_END_OF_BUFFER;
  }

lblReadBody:
  CurChar = chttpGetRawChar(s);
  if (CurChar == IOB_END_OF_BUFFER)
    return IOB_END_OF_BUFFER;
  s->CurrentChunkNumRead++;
  
  if (s->ChunkReadState == CRS_READING_CHUNK_BODY)
  {
    if (s->CurrentChunkNumRead <= s->CurrentChunkLen)
      return CurChar;
    // We read all data in this chunk.
    if (CurChar != '\n' && CurChar != '\r')
    {
      chttpSetParserError(s, HTTP_PARSER_ERROR_INVALID_CHUNK_BODY);
      return IOB_END_OF_BUFFER;
    }
    if (s->CurrentChunkNumRead - s->CurrentChunkLen == 1)
      goto lblReadBody;
    // We consumed everything in this chunk. Let's wait for the next chunk
    s->ChunkReadState = CRS_READING_CHUNK_HEADER;
    
    goto lblGetCharEntry;
  }
  
  // Not a chunked read. We also use s->CurrentChunkNumRead to count.
  if (s->ResponseContentLength && s->ResponseContentLength == s->CurrentChunkNumRead)
    s->ConsumedAllData = 1;
  
  return CurChar;
}

const char *chttpFetchRequestGetOrPostVarStr(TCHttp *s, const char *varname, char *buf, uint32_t maxlen)
{ // 
  const char *v;

  v = chttpFetchRequestGetOrPostVar(s, varname);

  if (v != NULL)
  {
    strncpy(buf, v, maxlen);
    if (strlen(v) > maxlen)
      buf[maxlen] = '\0';
    return buf;
  }
  return NULL;
}

const char *chttpGetConnectionStateStr(uint32_t ConnectionState)
{
  switch (ConnectionState)
  {
    case cstJUST_INITIALIZED: return "stJUST_INITIALIZED"; 
    case cstCONNECTING: return "cstCONNECTING";
    case cstRESOLVING_DNS: return "cstRESOLVING_DNS";
    case cstPARSING_HTTP_VERSION: return "cstPARSING_HTTP_VERSION";
    case cstPARSING_HTTP_STATUS_CODE: return "cstPARSING_HTTP_STATUS_CODE";
    case cstPARSING_HTTP_STATUS_STRING: return "cstPARSING_HTTP_STATUS_STRING";
  }
  return "UNKNOWN STATE";
}
TBool chttpAddFileToUpload(TCHttp *s, const char *FileFullPath, uint32_t MimeType)
{ // http://stackoverflow.com/questions/8659808/how-does-http-file-upload-work
  THttpCUplFile *U = (THttpCUplFile *)chttpMAlloc(s, sizeof(THttpCUplFile));
  
  U->FileName = chttpStrDup(s, FileFullPath);
  U->FileContent = mbInitNewByReadingFile(FileFullPath, 0, 0, MAP_POPULATE, TRUE);
  if (U->FileContent)
  {
    U->MimeType = MimeType;
    U->Next = s->FilesToUpload;
    s->FilesToUpload = U;
    return TRUE;
  } 
  return FALSE;
}

/**
 * @brief chttpExtractCharSet extracts character set from Content-Type header
 * @param s TCHttp *
 * @return TCharSet
 */
TCharSet chttpExtractCharSet(TCHttp *chttp)
{
  const char *s = chttpGetResponseHeader(chttp, "Content-Type");

  if (s)
  {
    //ext/html; charset=iso-8859-1
    s = strcasestr(s, "charset");
    if (s)
    {
      while(*s && (*s == '=' || isspace(*s)))
        s++;
      if (*s)
      {
        char TBuf[64], *dp=TBuf;
        while (*s && !isspace(*s) && *s != '\n' && *s != '\r' && (dp-TBuf < 63))
        {
          *dp = *s;
          ++dp;
          ++s;
        }
        *dp = '\0';
        return charsetParse(TBuf);
      }
    }
  }
  return CHARSET_NONE;
}

void chttpPrintResponseHeaders(TCHttp *s)
{
  TKeyValue *KV;
  TDLLNode *Node;
  chttpForEachResponseHeaderFIFO(s, Node)
  {
    KV = (TKeyValue *)dllGetContainerStructPtr(Node, TKeyValue);
    DBGPRINT(DBGLVL_DBG,  "%s: %s\n", KV->KeyAsStrPtr, KV->ValueAsStrPtr);
  }
}
/**
 * Internally called by chttpStateMachine when parsing of http headers is done
 * @param s
 * @return If TRUE, we stop parsing. If FALSE, we continue parsing body
 */
#if !defined(DEBUG) 
static 
#endif
void chttpHeaderParseCompleted(TCHttp *s)
{
  const char *tmpptr;
  
#if defined(HCDEBUG)
  dbglogSend3("chttpHeaderParseCompleted called\n");
  chttpPrintResponseHeaders(s);
#endif
  smbClear(s->LastElementData); // We clear LastElementData now. It will contain response body
  s->HeaderParseCompleted = 1;
  s->CurrentChunkNumRead = 0; // This is a very important variable to count how many chars are read in the body or in the current chunk in the body
  tmpptr = chttpGetResponseHeader(s, "Transfer-Encoding");
  if (tmpptr != NULL)
  {
    if (strcasecmp(tmpptr, "chunked") == 0)
    {
      s->ChunkReadState = CRS_READING_CHUNK_HEADER;
      s->ChunkHeaderAndTrailerData = smbInitNew(128);
    }
  }
  
  tmpptr = chttpGetResponseHeader(s, "Connection");
  if (tmpptr != NULL)
  {
    //DBGPRINT(DBGLVL_DBG,  "httpGetResponseHeader(s, 'Connection'): '%s'\n",tmpptr);
    if (strcasecmp(tmpptr,"keep-alive") == 0)
    { 
      s->KeepAlive = 1;
      #if defined(HDEBUG)
        dbglogSend3("KEEP ALIVE!!!!!!!!!!!\n");
      #endif
    } else s->KeepAlive = 0;
  } 
  else {
    // For http 1.1, all connections are persistent by default!!
    // https://en.wikipedia.org/wiki/HTTP_persistent_connection: 
    if (chttpGetResponseProtocol(s) >= HTTP_VERSION_1_1)
      s->KeepAlive = 1;
  }
  
  tmpptr = chttpGetResponseHeader(s, "Content-length");
  if (tmpptr != NULL)
    s->ResponseContentLength = strtoul(tmpptr, NULL, 10);
  else s->ResponseContentLength = 0;
  
  #if defined(HDEBUG)
    DBGPRINT(DBGLVL_DBG,  "Done parsing headers. Method: %u Content-length: %llu\n",chttpGetRequestMethod(s), (unsigned long long int)s->ResponseContentLength);
  #endif
  
  //httpDumpGPCVars(s,NULL);
  
  if (chttpGetRequestMethod(s) == HTTP_METHOD_GET)
  {
    tmpptr = chttpGetResponseHeader(s, "Upgrade");
    if (tmpptr != NULL)
    {
      s->ConsumedAllData = 1;
      if (strcasecmp(tmpptr,"websocket") != 0)
      {
        chttpSetParserError(s, HTTP_PARSER_ERROR_METHOD_NOT_IMPLEMENTED);
        return;
      }
    } 
    if (s->ResponseContentLength == 0 && s->ChunkReadState != CRS_READING_CHUNK_HEADER)
      s->ConsumedAllData = 1;
    return;
  }
  else if (chttpGetRequestMethod(s) == HTTP_METHOD_HEAD || chttpGetRequestMethod(s) == HTTP_METHOD_OPTIONS)
    s->ConsumedAllData = 1;
}
#if !defined(DEBUG) 
static 
#endif
TBool chttpNewDataIsAvailable (TIOBuf *io, TMemInputBuffer *mib)
{ 
  assert (io && io->ExtraData.p);
  TCHttp *s = CAST(io->ExtraData.p, TCHttp *);
  
  if (unlikely(!s))
    return FALSE;
  s->LastInputChunk = mib;
#if defined(HDEBUG)
  DBGPRINT(DBGLVL_DBG,  "MpxCycle#%llu chttpNewDataIsAvailable: %u bytes: [%.*s]\n", (unsigned long long)mpxGetCycleNo(iobGetMultiplexer(io)), DataSize, (int)(DataSize>1024 ? 1024 : DataSize),DataBuf);
#endif
  if (chttpGetState(s) == cstHTTP_REQUEST_SEND_WAITING_FOR_REPLY)
    chttpSetState(s, cstPARSING_HTTP_VERSION);
  
   char *tmpptr;
  uint16_t State;
  int32_t CurElemLen;
  int16_t CRLF, CurChar;
  int16_t PrevChar;
#define AddCurCharToLastElem() smbSendChar(s->LastElementData, (uint8_t)CurChar)
#define ClearLastElem() smbClear(s->LastElementData)
  
  PrevChar = 0;
  do
  {
    CurChar = chttpGetChar(s);
    if (CurChar == IOB_END_OF_BUFFER)
      break;
    if (s->HeaderParseCompleted)
    {
      AddCurCharToLastElem();
    }
    else
    {
      CRLF = (CurChar == '\n' && PrevChar == '\r');// || (CurChar == '\n' && PrevChar == '\r'));
      CurElemLen = smbGetLen(s->LastElementData);
      State = chttpGetState(s);
      switch(State)
      {
        case cstPARSING_HTTP_VERSION:
          if (CurChar == 32)
          {
            s->HttpResponseVersion = HTTP_VERSION_UNDEFINED;
            if (smbGetCharAt(s->LastElementData,5) == '1' && (smbGetCharAt(s->LastElementData,6) == '.'))
            {
              if (smbGetCharAt(s->LastElementData,7) == '0')
                s->HttpResponseVersion = HTTP_VERSION_1_0;
              else if (smbGetCharAt(s->LastElementData,7) == '1')
                s->HttpResponseVersion = HTTP_VERSION_1_1;
            }
            //DBGPRINT(DBGLVL_DBG,  "Protocol : %u %c %c %c\n",s->HttpRequestVersion,mbGetCharAt(s->LastElementData,5),mbGetCharAt(s->LastElementData,6),mbGetCharAt(s->LastElementData,7));
            if (unlikely(s->HttpResponseVersion == HTTP_VERSION_UNDEFINED))
              chttpSetParserError(s, HTTP_PARSER_ERROR_INVALID_HTTP_VERSION);
            else chttpSetState(s, cstPARSING_HTTP_STATUS_CODE);
          } 
          else {
            if (unlikely(CurElemLen > 9))
              chttpSetParserError(s, HTTP_PARSER_ERROR_INVALID_HTTP_VERSION);
            else AddCurCharToLastElem();
          }
          break;
        case cstPARSING_HTTP_STATUS_CODE:
          if (CurChar == ' ' || CRLF)
          {
            smbTerminateStringSafe(s->LastElementData);
            s->ResponseStatusCode = (uint16_t)atoi((const char *)smbGetBuf(s->LastElementData));
            chttpSetState(s, cstPARSING_HTTP_STATUS_STRING);
          } 
          else {
            if (unlikely(CurElemLen > 9))
              chttpSetParserError(s, HTTP_PARSER_ERROR_INVALID_HTTP_STATUS_CODE);
            else AddCurCharToLastElem();
          }
          break;
        case cstPARSING_HTTP_STATUS_STRING:
          if (CRLF)
          {
            smbTerminateStringSafe(s->LastElementData);
            chttpSetState(s, cstPARSING_HEADER_VAR_NAME);
          } 
          else {
            if (unlikely(CurElemLen > 500))
              chttpSetParserError(s, HTTP_PARSER_ERROR_INVALID_HTTP_STATUS_CODE);
            else AddCurCharToLastElem();
          }
          break;
        case cstPARSING_HEADER_VAR_NAME:
          if (CurElemLen > MAX_GPC_VAR_NAME_LEN) // Maximum variable name length is 64 characters
          {
            #if defined(HDEBUG)
            dbglogSend3("Variable name is too long or too short for a request header variable\n");
            #endif
            chttpSetParserError(s, HTTP_PARSER_ERROR_VARNAME_TOO_LONG);
          }
          else if (CurChar == ':')
          {
            if (CurElemLen)
            {
              smbTerminateStringSafe(s->LastElementData);
              if (strcasecmp((const char *)smbGetBuf(s->LastElementData),"Set-Cookie") == 0)
              { // This is a cookie. We must process it differently
                chttpSetState(s, cstPARSING_COOKIE_NAME);
                s->LastCookie = (TClientHTTPCookie *)chttpMAlloc(s, sizeof(TClientHTTPCookie));
                memset(s->LastCookie, 0, sizeof(TClientHTTPCookie));
              }
              else {
                s->LastVarName = chttpMAlloc(s, CurElemLen+1);
                UnEscapeStr(
                    (const char *)smbGetBuf(s->LastElementData),
                    s->LastVarName,
                    CurElemLen+1);
                chttpSetState(s, cstPARSING_HEADER_VAR_VALUE);
              }
            }
            else {
              chttpSetParserError(s, HTTP_PARSER_ERROR_HEADER_VARNAME_NOT_FOUND);
            }
          } 
          else if (CRLF)
          { // An empty line means we're done processing header!
            chttpHeaderParseCompleted(s);
          }
          else AddCurCharToLastElem();
          break;

        case cstPARSING_HEADER_VAR_VALUE:
          if (unlikely(CurElemLen > MAX_GPC_VAR_VALUE_LEN)) // Maximum variable name length is 64 characters
          {
            chttpSetParserError(s, HTTP_PARSER_ERROR_VARNAME_TOO_LONG);
          } 
          else if (CRLF)
          {
            smbSetCharAt(s->LastElementData, CurElemLen-1, '\0'); // We must delete \r at the end
            tmpptr = chttpMAlloc(s, CurElemLen);
            UnEscapeStr((const char *)smbGetBuf(s->LastElementData), tmpptr, CurElemLen);
            chttpAddResponseHeader(s, s->LastVarName, FALSE, tmpptr, FALSE);
            chttpSetState(s, cstPARSING_HEADER_VAR_NAME);
          } 
          else {
            if (!(!CurElemLen && CurChar == ' ')) // We skip the first possible space before var value as in "Header: Value"
              AddCurCharToLastElem();
          }
          break;

        case cstPARSING_COOKIE_NAME:
          if (unlikely(CurElemLen > MAX_GPC_VAR_NAME_LEN)) // Maximum variable name length is 64 characters
          {
            #if defined(HDEBUG)
            dbglogSend3("Variable name is too long or too short for a uri variable\n");
            #endif
            chttpSetParserError(s, HTTP_PARSER_ERROR_VARNAME_TOO_LONG);
          } 
          else if (CurChar == '=')
          {
            if (likely(CurElemLen))
            {
              smbSendChar(s->LastElementData, '\0'); // Let's terminate string by adding \0 to the end.
              s->LastCookie->Name = chttpMAlloc(s, CurElemLen+1);
              UnEscapeStr((const char *)smbGetBuf(s->LastElementData), (char *)s->LastCookie->Name, CurElemLen+1);
              TKeyValue *KV = (TKeyValue *)chttpMAlloc(s, sizeof(TKeyValue));
              KV->KeyAsStrPtr = s->LastCookie->Name;
              KV->ValueAsVoidPtr = (void *)s->LastCookie;
              kvGetOrSetWithStrKey(&s->ResponseCookies, KV);
              chttpSetState(s, cstPARSING_COOKIE_VALUE);
            }
            else {
              // Normally this should not happen but let's try to fix it!
              ClearLastElem();
            }
          } 
          else if (CurChar == ';')
          { 
            ClearLastElem();
          }
          else if (CRLF)
          { 
            chttpSetState(s, cstPARSING_HEADER_VAR_NAME);
          }
          else AddCurCharToLastElem();
          break;

        case cstPARSING_COOKIE_VALUE:
          if (unlikely(CurElemLen > MAX_GPC_VAR_VALUE_LEN)) // Maximum variable name length is 64 characters
          {
            chttpSetParserError(s, HTTP_PARSER_ERROR_VARNAME_TOO_LONG);
          }
          else if (CurChar == ';')
          {
            if (unlikely(CurElemLen == 0))
              chttpSetParserError(s, HTTP_PARSER_ERROR_HEADER_VARNAME_NOT_FOUND);
            smbSendChar(s->LastElementData, '\0'); // Let's terminate string by adding \0 to the end.
            s->LastCookie->Value = chttpMAlloc(s, CurElemLen+1);
            UnEscapeStr((const char *)smbGetBuf(s->LastElementData), (char *)s->LastCookie->Value, CurElemLen+1);
            chttpSetState(s, cstPARSING_COOKIE_PROPERTY_NAME);
          } 
          else if (CRLF)
          {
            if (unlikely(CurElemLen == 0))
              chttpSetParserError(s, HTTP_PARSER_ERROR_HEADER_VARNAME_NOT_FOUND);
            smbSetCharAt(s->LastElementData, CurElemLen-1, '\0'); // We must delete : at the end
            s->LastCookie->Value = chttpMAlloc(s, CurElemLen+1);
            UnEscapeStr((const char *)smbGetBuf(s->LastElementData), (char *)s->LastCookie->Value, CurElemLen+1);
            chttpSetState(s, cstPARSING_HEADER_VAR_NAME);
          } else AddCurCharToLastElem();
          break;
        case cstPARSING_COOKIE_PROPERTY_NAME:
          if (unlikely(CurElemLen > MAX_GPC_VAR_NAME_LEN)) // Maximum variable name length is 64 characters
            chttpSetParserError(s, HTTP_PARSER_ERROR_VARNAME_TOO_LONG);
          else if (CurChar == '=')
          {
            smbSendChar(s->LastElementData, '\0'); // Let's terminate string by adding \0 to the end.
            s->LastCookie->LastPropertyName = chttpStrDupLen(s, (const char *)smbGetBuf(s->LastElementData), smbGetLen(s->LastElementData));
            chttpSetState(s, cstPARSING_COOKIE_PROPERTY_VALUE);
          }
          else if (CRLF)
          {
            if (unlikely(CurElemLen == 0))
              chttpSetParserError(s, HTTP_PARSER_ERROR_HEADER_VARNAME_NOT_FOUND);
            smbSetCharAt(s->LastElementData, CurElemLen-1, '\0'); // We must delete : at the end
            chttpSetState(s, cstPARSING_HEADER_VAR_NAME);

            tmpptr = (char *)smbGetBuf(s->LastElementData);
            if (strcasecmp(tmpptr, "Secure") == 0)
              s->LastCookie->Secure = 1;
            else if (strcasecmp(tmpptr, "HttpOnly") == 0)
              s->LastCookie->HttpOnly = 1;
          }
          else if (CurChar == ';')
          {
            smbSendChar(s->LastElementData, '\0'); // Let's terminate string by adding \0 to the end.
            tmpptr = (char *)smbGetBuf(s->LastElementData);
            if (strcasecmp(tmpptr, "Secure") == 0)
              s->LastCookie->Secure = 1;
            else if (strcasecmp(tmpptr, "HttpOnly") == 0)
              s->LastCookie->HttpOnly = 1;
            ClearLastElem();
          } else AddCurCharToLastElem();
          break;
        case cstPARSING_COOKIE_PROPERTY_VALUE:
          if (unlikely(CurElemLen > MAX_GPC_VAR_NAME_LEN)) // Maximum variable name length is 64 characters
            chttpSetParserError(s, HTTP_PARSER_ERROR_VARNAME_TOO_LONG);
          else if (CurChar == ';' || CRLF)
          {
            if (CRLF)
            {
              smbSetCharAt(s->LastElementData, CurElemLen-1, '\0'); // We must delete : at the end
              chttpSetState(s, cstPARSING_HEADER_VAR_NAME);
            } 
            else {
              smbSendChar(s->LastElementData, '\0'); // Let's terminate string by adding \0 to the end.
              chttpSetState(s, cstPARSING_COOKIE_PROPERTY_NAME);
            }
            tmpptr = chttpStrDup(s, (const char *)smbGetBuf(s->LastElementData));
            if (strcasecmp(s->LastCookie->Name, "Expires") == 0)
              s->LastCookie->Expires = tmpptr;
            else if (strcasecmp(tmpptr, "Path") == 0)
              s->LastCookie->Path = tmpptr;
            else if (strcasecmp(tmpptr, "Domain") == 0)
              s->LastCookie->Domain = tmpptr;
          }
          else AddCurCharToLastElem();
          break;
      }
      // If we are just entering to a new state, we must clear state data buffer
      if (State != chttpGetState(s))
      {
        #if defined(DEBUG)
          //if (s->HeaderParseCompleted)
            //DBGPRINT(DBGLVL_DBG,  "State changed from %s to %s. Data : %s\n",httpGetConnectionStateStr(State),httpGetConnectionStateStr(httpGetState(s)),mbGetVal(s->LastElementData));
        #endif
        ClearLastElem();
        PrevChar = 0;
      } else PrevChar = CurChar;
    }
  } while (s->ParserError == HTTP_PARSER_ERROR_NONE && !s->ConsumedAllData);
  if (unlikely(s->ChunkHeaderAndTrailerData && smbGetLen(s->ChunkHeaderAndTrailerData) > 128))
    chttpSetParserError(s, HTTP_PARSER_ERROR_INVALID_CHUNK_BODY);
  /*if (s->ParserError)
  {
    DBGPRINT(DBGLVL_DBG,  "chttp Parser err: %u Str: %.*s\n", s->ParserError, (int)DataSize, DataBuf);
  }*/
  if (s->ConsumedAllData || s->ParserError != HTTP_PARSER_ERROR_NONE)
  {
    if (s->ParserError == HTTP_PARSER_ERROR_NONE && smbGetLen(s->LastElementData)>0)
    {
      // Let's check content encoding
      // If it's gzip or deflate, we need to decompress content
      const char *ContentEncoding = chttpGetResponseHeader(s,"Content-Encoding");
      int32_t CompressionMethod = ZLIB_COMPRESSION_NONE;
      if (ContentEncoding)
      {
        //DBGPRINT(DBGLVL_DBG,  "ContentEncoding: %s\n", ContentEncoding);
        if (strcasecmp(ContentEncoding, "gzip") == 0)
          CompressionMethod = ZLIB_COMPRESSION_GZIP;
        else if (strcasecmp(ContentEncoding, "deflate") == 0)
          CompressionMethod = ZLIB_COMPRESSION_DEFLATE;
        smbZlibDecompressSameBuf(s->LastElementData, CompressionMethod, 15);
        smbTerminateStringSafe(s->LastElementData);
      }
    }
    s->fncOnRequestCompleted(s);
    chttpDestroyAndFree(s);
    return TRUE;
  }
  return FALSE;
}

/**
 * ConstructCommonHeaderStr construct the common request header lines for both GET and POST requests
 * @param s TCHttp *
 * @param InitialBufSize unsigned int; the initial size of the output buffer to be constructed
 * @param CompleteHeader If TRUE, this is for a get request; the complete header will be returned with an empty CRLF line at the end
 * @return 
 */
#if !defined(DEBUG) 
static 
#endif
TMemBuf *ConstructCommonHeaderStr(TCHttp *s, unsigned int InitialBufSize)
{ // GET /path/to/file/index.html HTTP/1.0
  // RFC says that we must always send the maximum http version we can handle
  TKeyValue *KV;
  TDLLNode *Node;

  TMemBuf *O = mbInitNew(InitialBufSize);
  // If there is no post variables, we don't need to use post!
  if (s->RequestMethod == HTTP_METHOD_POST && kvIsEmpty(&s->RequestGetOrPOSTVars))
    s->RequestMethod = HTTP_METHOD_GET;
  
//  TParsedURI *A = ocGetLastConnectedAddr(s->OConn); // A->OriginalAddrStr
  //assert(A != NULL);
  if (!chttpGetRequestHeader(s, "User-Agent"))
    chttpAddRequestHeader(s, "User-Agent", FALSE, "NewsSearchCrawler", FALSE);
  //if (!chttpGetRequestHeader(s, "Accept-Encoding"))
    //chttpAddRequestHeader(s, "Accept-Encoding", FALSE, "gzip", FALSE);
  if (!chttpGetRequestHeader(s, "Accept"))
    chttpAddRequestHeader(s, "Accept", FALSE, "*/*", FALSE);
  if (!chttpGetRequestHeader(s, "Connection"))
    chttpAddRequestHeader(s, "Connection", FALSE, "Keep-Alive", FALSE);

  if (s->RequestMethod != HTTP_METHOD_GET || kvIsEmpty(&s->RequestGetOrPOSTVars))
    mbPrint(O, "%s %s HTTP/1.1\r\nHost: %s\r\n",
            httpGetMethodStr(s->RequestMethod),
            s->URIWithoutHost, s->Host);
  else 
  { // Get method. And we have some GET parameters to append to URI
    mbPrint(O, "%s %s?", httpGetMethodStr(s->RequestMethod), s->URIWithoutHost);
    unsigned t=0;
    kvForEachFIFO(&s->RequestGetOrPOSTVars, Node)
    {
      KV = (TKeyValue *)dllGetContainerStructPtr(Node, TKeyValue);
      if (t)
        mbSendChar(O, '&');
      mbEscapeStr(O, (const uint8_t *)KV->KeyAsStrPtr, 0);
      mbSendChar(O, '=');
      mbEscapeStr(O, (const uint8_t *)KV->ValueAsStrPtr, 0);
      t++;
    }
    mbPrint(O, " HTTP/1.1\r\nHost: %s\r\n",
            httpGetMethodStr(s->RequestMethod),
            s->Host);
  }
  // Then, we send the headers
  kvForEachFIFO(&s->RequestHeaders, Node)
  {
    KV = (TKeyValue *)dllGetContainerStructPtr(Node, TKeyValue);
    mbPrint(O, "%s: %s\r\n", KV->KeyAsStrPtr, KV->ValueAsStrPtr);
  }
  //DBGPRINT(DBGLVL_DBG,  "%.*s\n", (int)smbGetLen(O), O->smb.StrBuf);
  return O;
}

static void chttpAddCustomEncryptedLoginPacket(TCHttp *s, TCustomEncParamsForClient *P, TSimpleMemBuf *LoginPacket)
{
  const uint8_t EncType = cencGetEncTypeClient(P);
  TSimpleMemBuf smb;
  smbInit(&smb, 1600);
  cencPack(&smb, P, smbGetBuf(LoginPacket), (unsigned)smbGetLen(LoginPacket));

  DBGPRINT(DBGLVL_DBG, "Sending EncPack: %.*B\n", (int)smbGetLenAsUInt32(&smb), smbGetBuf(&smb));
  if (EncType == CUSTOM_ENC_TYPE_X25519_AND_NTRUPRIME)
  { // It will be custom encrypted connection with X25519 and NTRU Prime DH key exchange
    if (s->RequestMethod == HTTP_METHOD_GET)
      chttpAddRequestGetOrPOSTVarBase64(s, CENC_GCP_VNAME_HYBRID_B64, FALSE, (const char *)smbGetBuf(&smb), smbGetLenAsUInt32(&smb));
    else chttpAddRequestGetOrPOSTVarBin(s, CENC_GCP_VNAME_HYBRID_BIN, FALSE, (const char *)smbGetBuf(&smb), smbGetLenAsUInt32(&smb), TRUE);
  }
  else if (EncType == CUSTOM_ENC_TYPE_X25519)
  { // It will be custom encrypted connection with X25519
    if (s->RequestMethod == HTTP_METHOD_GET)
      chttpAddRequestGetOrPOSTVarBase64(s, CENC_GCP_VNAME_X25519_B64, FALSE, (const char *)smbGetBuf(&smb), smbGetLenAsUInt32(&smb));
    else chttpAddRequestGetOrPOSTVarBin(s, CENC_GCP_VNAME_X25519_BIN, FALSE, (const char *)smbGetBuf(&smb), smbGetLenAsUInt32(&smb), TRUE);
  }
  else if (EncType == CUSTOM_ENC_TYPE_PSK_HOHHA_SYMM)
  { // Custom encryption with pre-shared hohha key
    if (s->RequestMethod == HTTP_METHOD_GET)
      chttpAddRequestGetOrPOSTVarBase64(s, CENC_GCP_VNAME_PSK_B64, FALSE, (const char *)smbGetBuf(&smb), smbGetLenAsUInt32(&smb));
    else chttpAddRequestGetOrPOSTVarBin(s, CENC_GCP_VNAME_PSK_BIN, FALSE, (const char *)smbGetBuf(&smb), smbGetLenAsUInt32(&smb), TRUE);
  }
  smbDestroyAndFree(&smb);
}

/**
 * chttpSendRequest sends a request to server
 * @param s TCHttp *
 * @param URIWithoutHost URI to be requested from server. But without Host:Port part
 * @param TCHTTPfncOnRequestCompleted function
 *        typedef void (*TCHTTPfncOnRequestCompleted)(TCHttp *s);
 *        This function will be called on success or on error when the request is completed.
 *        And when this callback function returns, TCHttp will be automatically destroyed
 * @param ForceMultipartEncoding If TRUE, even if we don't have a file to upload, Content-Type: multipart/form-data will be used
 */
void chttpSendRequest(
  TCHttp *s, 
  const char *URIWithoutHost, 
  TCHTTPfncOnRequestCompleted fncOnRequestCompleted,
  TBool ForceMultipartEncoding)
{
  // This variables must be initialized before EVERY SINGLE URI TO BE RETRIEVED!!
  if (unlikely(!s->io) || s->io->Closed)
  {
    s->ParserError = HTTP_PARSER_ERROR_NOT_CONNECTED;
    fncOnRequestCompleted(s);
    chttpDestroyAndFree(s);
  }
  s->io->ExtraData.p = s;
  TMemBuf *StrsArr[32];
  unsigned NFElems = 0;

  s->fncOnRequestCompleted = fncOnRequestCompleted;
  s->URIWithoutHost = chttpStrDup(s, URIWithoutHost);
  s->State = cstHTTP_REQUEST_SEND_WAITING_FOR_REPLY;
  TMemBuf *H = ConstructCommonHeaderStr(s, 511);
  TKeyValue *KV;
  TDLLNode *Node;

  if (chttpGetRequestMethod(s) == HTTP_METHOD_GET)
  {
    // At the end of the header, there must be an empty line(only CRLF)
    mbSendChar(H, '\r');
    mbSendChar(H, '\n');
    StrsArr[NFElems++] = H;
    /*DBGPRINT(DBGLVL_DBG,  "---request begin---\n%.*s---request ends---\n",
           (int)smbGetLen(H),
           smbGetBuf(H));*/
  }
  else {
    // This is a post request
    // If we'll upload files, we must choose Content-Type: multipart/form-data; boundary=...
    // Else we'll use Content-Type: application/x-www-form-urlencoded encoding
    THttpCUplFile *U = s->FilesToUpload;
    unsigned long long ContentLength = 0;
    if (U == NULL && ForceMultipartEncoding == 0)
    {// It's a regular application/x-www-form-urlencoded post string
      // text1=text+default&text2=a%CF%89b&file1=a.txt&file2=a.html&file3=binary
      StrsArr[NFElems++] = H;
      if (s->RequestContentType == MIME_APPLICATION_X_WWW_FORM_URLENCODED)
      {
        TSimpleMemBuf *B = smbInitNew(200);
        kvForEachFIFO(&s->RequestGetOrPOSTVars, Node)
        {
          KV = (TKeyValue *)dllGetContainerStructPtr(Node, TKeyValue);
          if (smbGetLen(B))
            smbSendChar(B, '&');
          smbSendStr2(B, (const uint8_t *)KV->KeyAsStrPtr, KV->KeyStrLen);
          smbSendChar(B, '=');
          smbEscapeStr(B, (const uint8_t *)KV->ValueAsStrPtr, FALSE);
        }
        // We send content-length as the last header line
        mbPrint(H, "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %llu\r\n\r\n",
                (unsigned long long int)smbGetLen(B)); 
        mbSendStr2(H, smbGetBuf(B), smbGetLen(B));
        smbDestroyAndFree(B);
      }
      else {
        mbSendStr(H, "Content-Type: ");
        mbSendStr(H, MIMEGetString(s->RequestContentType));
        if (s->ReqBody && mbGetLen(s->ReqBody))
        {
          mbSendStr(H, "\r\nContent-Length: ");
          mbSendUInt64AsStr(H, mbGetLen(s->ReqBody));
          mbSendChar(H, '\r');
          mbSendChar(H, '\n');
          mbSendChar(H, '\r');
          mbSendChar(H, '\n');
          StrsArr[NFElems++] = s->ReqBody;
        }
        else {
          mbSendStr(H, "\r\nContent-Length: 0\r\n\r\n");
        }
      }
    }
    else {
      char BoundaryStr[128];
      unsigned FileNo = 0;
      sprintf(BoundaryStr,"--A99A%llu",(unsigned long long int)mpxGetCycleNo(chttpGetMultiplexer(s)));
      mbPrint(H, "Content-Type: multipart/form-data; boundary=%s\r\nContent-Length: ", BoundaryStr);
      
      StrsArr[NFElems++] = H;
      H = mbInitNew(200);
      
      kvForEachFIFO(&s->RequestGetOrPOSTVars, Node)
      {
        KV = (TKeyValue *)dllGetContainerStructPtr(Node, TKeyValue);
       
        mbPrint(H, "--%s\r\nContent-Disposition: form-data; name=\"%.*s\"\r\n\r\n%.*s\r\n", 
          BoundaryStr,
          (int)KV->KeyStrLen,
          KV->KeyAsStrPtr,
          (int)KV->ValueStrLen,
          KV->ValueAsStrPtr
        );
      }
      U = s->FilesToUpload;
      while (U)
      {
        mbPrint(H, "--%s\r\n"
                   "Content-Disposition: form-data; name=\"File%u\"; filename=\"%s\"\r\n"
                   "Content-type: %s\r\n"
                   "Content-Transfer-Encoding: binary\r\n\r\n", 
          BoundaryStr,
          FileNo,
          ExtractFileNameFromFullPath(U->FileName),
          MIMEGetString(U->MimeType)
        );
        FileNo++;
        // Here, we must flush current buffer
        // Because, the next buffer will contain just an mmapped pointer
        ContentLength += mbGetLen(H) + mbGetLen(U->FileContent);
        StrsArr[NFElems++] = H;
        StrsArr[NFElems++] = U->FileContent;
        assert(NFElems<64);
        H = mbInitNew(200);
        mbSendStr2(H, "\r\n", 2); 
        U->FileContent = NULL;
        U = U->Next;
      } 
      // Now, we must print out the last boundary
      // And content length header
      mbPrint(H, "--%s--", BoundaryStr);
      StrsArr[NFElems++] = H;
      ContentLength += mbGetLen(H);
      mbPrint(StrsArr[0], "%llu\r\n\r\n", ContentLength);
    }
  }
  iobAddChainToFlushQueue(s->io, StrsArr, NFElems, IOQ_FLAG_LAST_ELEMENT_OF_A_SERIE);
}

/**
 * chttpSendRequest sends a custom encrypted request to server
 * @param s TCHttp *
 * @param URIWithoutHost URI to be requested from server. But without Host:Port part
 * @param EncParams TCustomEncParamsForClient * Custom encryption parameters, any custom encryption will be used. Or NULL
 * @params DataToSendInEcryptedForm TSimpleMemBuf *
 *         Any data(usually login parameters + any data) buffer to be encrypted and to be sent to server
 *         The name of GET/POST variable will depend on encryption type
 *
 * @param TCHTTPfncOnRequestCompleted function
 *        typedef void (*TCHTTPfncOnRequestCompleted)(TCHttp *s);
 *        This function will be called on success or on error when the request is completed.
 *        And when this callback function returns, TCHttp will be automatically destroyed
 * @param ForceMultipartEncoding If TRUE, even if we don't have a file to upload, Content-Type: multipart/form-data will be used
 */
void chttpSendCustomEncryptedRequest(
  TCHttp *s,
  const char *URIWithoutHost,
  TCustomEncParamsForClient *EncParams,
  TSimpleMemBuf *DataToSendInEcryptedForm,
  TCHTTPfncOnRequestCompleted fncOnRequestCompleted,
  TBool ForceMultipartEncoding)
{
  if (DataToSendInEcryptedForm && smbGetLen(DataToSendInEcryptedForm))
  {
    if (EncParams)
      chttpAddCustomEncryptedLoginPacket(s, EncParams, DataToSendInEcryptedForm);
    else chttpAddRequestGetOrPOSTVarBase64(s,
                                           CENC_GCP_VNAME_PTEXT_B64,
                                           FALSE,
                                           (const char *)smbGetBuf(DataToSendInEcryptedForm),
                                           smbGetLenAsUInt32(DataToSendInEcryptedForm)); // Plaintext login data
  }
  chttpSendRequest(s, URIWithoutHost, fncOnRequestCompleted, ForceMultipartEncoding);
}

// For websocket client, we always send the same security key and expect the same security response. The sample is taken from wikipedia
#define WEBSOCK_SECKEY_REQ_STR "x3JJHMbDL1EzLkh9GBhXDw=="
#define WEBSOCK_SECKEY_RESP_STR "HSmrc0sMlYUkAGmm5OPpG2HaGWk="

#if !defined(DEBUG) 
static 
#endif
void chttpCheckNegotiatedHeadersAndSetThemInUnderlyingIO(TCHttp *s)
{
  TKeyValue *KVPtr;
  TDLLNode *Node;
  // We also check returned headers from server and adjust our settings according to approved settings by server
  chttpForEachResponseHeaderFIFO(s, Node)
  {
    KVPtr = (TKeyValue *)dllGetContainerStructPtr(Node, TKeyValue);
    if (strcasecmp(KVPtr->KeyAsStrPtr, "Sec-WebSocket-Extensions") == 0)
    { 
      if (strcasestr(KVPtr->ValueAsStrPtr, "PlainTCPAfterUpgrade") != NULL)
      {
        // Server accepted our PlainTCPAfterUpgrade extension negotiation
        // After upgrade, connection will continue as a plain tcp connection
        #if defined(HCDEBUG)
          DBGPRINT(DBGLVL_DBG, "%s", "Server accepted our offer for PlainTCPAfterUpgrade extension. We adjust our settings accordingly.\n");
        #endif
        s->io->PlainTCPAfterWebSocketUprade = 1;
      }
      else if (strcasestr(KVPtr->ValueAsStrPtr, "NoXORMask") != NULL)
      {
        // Server accepted our noxormask extension negotiation 
        #if defined(HCDEBUG)
          DBGPRINT(DBGLVL_DBG, "%s", "Server accepted our offer for NoXORMask extension. We adjust our settings accordingly.\n");
        #endif
        s->io->NoXORMaskForWebSocket = 1;
      }
      else if (strcasestr(KVPtr->ValueAsStrPtr, "lz4-a99a") != NULL)
      {
        // Server accepted our lz4 compression extension negotiation 
        #if defined(HCDEBUG)
          DBGPRINT(DBGLVL_DBG, "%s", "Server accepted our offer for LZ4 compression extension. We adjust our settings accordingly.\n");
        #endif
        s->io->CompressionType = IOB_COMP_LZ4;
      }
    }
  }
}
/**
 * chttpUpgradeUnderlyingIOToWebsocket converts chttp's underlying TOutgoingConn's underlying iobuffer's socket profile to websocket and returns it
 *   This function must  be called from chttp's fncOnRequestCompleted callback handler of a websocket request!!
 *   
 * @param s Httpclient object upgraded
 * @param fncOnNewCommandOrFrame When new data arrives to this websocket, this callback will be called
 *        Prototype is: typedef void (*TfncOnNewCommandOrFrame)(TIOFrame *); 
 * @param TfncIOBufGetHohhaEncryptionKey Callback function pointer to acquire hohha communication key 
 *        If you will use plaintext or SSL connection for this communication, set to NULL
 *        If you want to use hohha encryption for this websocket communication, set this to callback function pointer
 *        every time we receive or send a hohha communication packet
 * @param TimeoutInMs Maximum inactivity time for this websocket in epoll cycles. If set 0, timeout will be disabled
 * @return TIOBuf * or NULL on error
 */
TIOBuf *chttpConvertUnderlyingIOToWebsocketProfile(TCHttp *s, TfncOnNewCommandOrFrame fncOnNewCommandOrFrame, TfncIOBufGetHohhaEncryptionKey fncIOBufGetHohhaEncryptionKey, unsigned int TimeoutInMs)
{
  if (s->ParserError == HTTP_PARSER_ERROR_NONE)
  {
    chttpCheckNegotiatedHeadersAndSetThemInUnderlyingIO(s);
    TIOBuf *io = chttpDetachUnderlyingIO(s);
    io->SocketProfile->CommProtocol = protoWebSocket;
    io->SocketProfile->fncOnNewCommandOrFrame = fncOnNewCommandOrFrame; // Set websocket handler function
    //io->SocketProfile->MustCloseWhenDone = 0;
    io->SocketProfile->Timeout = TimeoutInMs;
    io->SocketProfile->fncGetHohhaEncryptionKeyWebSocket = fncIOBufGetHohhaEncryptionKey;
    io->SocketProfile->TimeoutBeforeLogin    = 111111;
    // We clear old timeout. Because, it was an http connection
    // And set the new timeout if there is any
    iobClearLastSocketInactivityTimeout(io);
    if (TimeoutInMs)
      iobResetSocketInactivityTimeout(io);
    // Now, we create a 
    return io;
  }
  return NULL;
}

/**
 * chttpUpgradeToWebSocket is used to connect to an http server in order to establish a websocket connection
 * This is similar to chttpSendRequest function. But it is used to establish a websocket connection
 * @param s TCHttp *
 * @param URIWithoutHost Request uri(without host part e.g. /chat)
 * @param WebSocketExtensionsToOffer An OR'ed combination of WEBSOCK_EXTENSION_XXX constants
 * @param TCHTTPfncOnRequestCompleted function
 *        typedef void (*TCHTTPfncOnRequestCompleted)(TCHttp *s);
 *        This function will be called on success or on error when the request is completed.
 *        And when this callback function returns, TCHttp will be automatically destroyed
 */
void chttpUpgradeToWebSocket(TCHttp *s, 
  const char *URIWithoutHost,
  uint64_t WebSocketExtensionsToOffer,
  TCHTTPfncOnRequestCompleted fncOnRequestCompleted)
{
  // This variables must be initialized before EVERY SINGLE URI TO BE RETRIEVED!!
  if (unlikely(!s->io))
  {
    s->ParserError = HTTP_PARSER_ERROR_NOT_CONNECTED;
    fncOnRequestCompleted(s);
    chttpDestroyAndFree(s);
  }
  s->io->ExtraData.p = s;
  chttpSetRequestMethod(s, HTTP_METHOD_GET);
  s->fncOnRequestCompleted = fncOnRequestCompleted;
  s->URIWithoutHost = chttpStrDup(s, URIWithoutHost);
  s->State = cstHTTP_REQUEST_SEND_WAITING_FOR_REPLY;
  TMemBuf *H = ConstructCommonHeaderStr(s, 1000);
  mbSendStr(H, "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: " WEBSOCK_SECKEY_REQ_STR "\r\n");
  
  // We also suggest our desired extensions
  // NoXORMask is our own private extension to supress xor masking in communications
  // LZ4 is our own private extension to compress data payloads with lz4 compression
  if ((WebSocketExtensionsToOffer & WEBSOCK_EXTENSION_NOXORMASK_NUM))
    mbSendStr(H, "Sec-WebSocket-Extensions: NoXORMask\r\n");
  if ((WebSocketExtensionsToOffer & WEBSOCK_EXTENSION_LZ4_NUM))
    mbSendStr(H, "Sec-WebSocket-Extensions: LZ4-A99A\r\n");
  // Sec-WebSocket-Extensions: Request-Tracking is for request tracking
  // We add extra 4 bytes to header
  // RSV2 bit is set, Last 4 four bytes of the header, in least significant byte order describes a REQUEST_ID
  // For an incoming connection, receiving a frame with RSV2 bit set, means, 
  //   that frame contains a new request coming from client to server REQUEST_ID
  // For an outgoing connection, receiving a frame with RSV2 bit set, means, 
  //   that frame contain a response to the request REQUEST_ID
  if ((WebSocketExtensionsToOffer & WEBSOCK_EXTENSION_PLAIN_TCP))
    mbSendStr(H, "Sec-WebSocket-Extensions: PlainTCPAfterUpgrade\r\n");

  mbSendStr(H, "\r\n");
#if defined(HCDEBUG)
  DBGPRINT(DBGLVL_DBG, "\n\nSending http data: %.*s\n\n", (int)mbGetLen(H), (char *)mbGetBuf(H));
#endif
  iobAddToFlushQueue(s->io, H, IOQ_FLAG_LAST_ELEMENT_OF_A_SERIE);
}

void chttpUpgradeToWebSocketWithCustomEnc(TCHttp *s,
  const char *URIWithoutHost,
  TCustomEncParamsForClient *EncParams,
  TSimpleMemBuf *LoginParamsAsPlainText,
  uint64_t WebSocketExtensionsToOffer,
  TCHTTPfncOnRequestCompleted fncOnRequestCompleted)
{
  if (EncParams && LoginParamsAsPlainText && smbGetLen(LoginParamsAsPlainText))
    chttpAddCustomEncryptedLoginPacket(s, EncParams, LoginParamsAsPlainText);
  chttpUpgradeToWebSocket(s, URIWithoutHost, WebSocketExtensionsToOffer, fncOnRequestCompleted);
}

void chttpDestroyUnderlyingIO(TCHttp *s)
{
#if defined(HCDEBUG)
  DBGPRINT(DBGLVL_DBG, "%s", "chttpDestroyUnderlyingIO called\n");
#endif
  TIOBuf *io = s->io;
  if (io)
  {
    chttpDetachUnderlyingIO(s);
    iobClose(io, IOB_DESTROY_REASON_PROGRAMMATIC, FALSE);
  }
}

/**
 * 
 * 
 * @param s TCHttp *
 */

/**
 * chttpDetachUnderlyingIO cuts the relationship between TCHttp *s and underlying TIOBuf and returns io 
 * When an io is detached from TCHttp, it survives after TCHttp is destroyed!
 * @param s TCHttp *
 * @return Underlying, detached io TIOBuf *
 */
TIOBuf *chttpDetachUnderlyingIO(TCHttp *s)
{
#if defined(HCDEBUG)
  DBGPRINT(DBGLVL_DBG, "%s", "chttpDetachUnderlyingIO called\n");
#endif
  TIOBuf *io = s->io;
  if (io)
  {
    io->ExtraData = s->ExtraData;
    assert(io->SocketProfile != NULL);
    io->SocketProfile->fncOnClose = NULL;
    io->SocketProfile->fncIOBufNewRawDataIsAvailable = NULL;
    s->io = NULL;
    iobDecRefCounter(io);
  }
  return io;
}

void chttpDestroyAndFree(TCHttp *s)
{
  //DBGPRINT(DBGLVL_DBG, "chttpDestroyAndFree called. io: is %s\n", (s->io ? " null" : " NOT NULL"));
  THttpCUplFile *U = s->FilesToUpload;
  while (U)
  {
    if (U->FileContent)
      mbDestroyAndFree(U->FileContent);
    U = U->Next;
  }
  if (s->LastElementData)
    smbDestroyAndFree(s->LastElementData);
  // We don't destroy outgoing connection object here
  // We just cut its relationship with this object
  chttpDetachUnderlyingIO(s);
  if (s->ChunkHeaderAndTrailerData != NULL)
    smbDestroyAndFree(s->ChunkHeaderAndTrailerData);
  DestroyChunk(&s->ChunkInfo);
  if (s->FreeThisStructure)
    mpxmmFree(chttpGetMultiplexer(s), s);
}


#if defined(USE_OLD_CODE)
/**
 * chttpSetCustomEncParamsX25519AndNTRUPrime sets custom X25519 and Ntru Prime hybrid encryption parameters
 *  initiates a websocket connection via X25519 DH key exchange
 * Server's X25519 public key and client X25519 private key will give us a common 32 bytes key SK1
 * Then we create another 32 bytes random bytes we call SK2
 * We encrypt SK2 with Server's NTRU Prime public key
 * We xor plaintext SK1 and SK2 byte by byte and we obtain 32 byte result TSK
 * We use TSK as 32 bytes seed for our custom Hohha PRNG object
 * We create a 32 bytes HOHHA Key SK(With a proper header) by using
 * Hohha PRNG object for random number generation seeded with TSK
 * We encrypt mb's content with SK with hohha
 * @param s TChttp pointer
 * @param ClientX25519KeyPair Client's X25519 key pair
 * @param SrvKeyID is the ID of the PSK on server
 * @param SrvX25519 public key
 * @param SrvNTRUPubKey Server's NTRU Prime public key
 * @param NumJumpsForCommonKey
 * @param ReqData TMemBuf
 * @param HohhaSessionKey This key is the real session key to be used
 */
void chttpSetCustomEncParamsX25519AndNTRUPrimeOld(
  TCHttp *chttp,
  TX25519KeyPair *ClientX25519KeyPair,
  unsigned SrvKeyID,
  uint8_t *SrvX25519PubKey,
  const unsigned char *SrvNTRUPubKey,
  unsigned NumJumpsForCommonKey,
  const uint8_t *HohhaSessionKey,
  TMemBuf *ReqData)
{
  uint8_t SK1[32];
  unsigned char SK2[crypto_kem_BYTES], SK2CipherText[crypto_kem_CIPHERTEXTBYTES];
  uint8_t CommonHohhaKey[xorComputeKeyBufLen(COMMON_HOHHA_XOR_KEY_BODY_LEN)];

  char *NumBuf = (char *)chttpMAlloc(chttp, 8);
  UInt32ToStr(NumJumpsForCommonKey, NumBuf);

  char *KeyIDStrBuf = chttpMAlloc(chttp, 12);
  UInt32ToStr(SrvKeyID, KeyIDStrBuf);

  // We compute SK1; the first part of common hohha xor key rng seed with x25519
  curve25519_donna(SK1, ClientX25519KeyPair->PrvKey, SrvX25519PubKey);
  /**
  unsigned char c[crypto_kem_CIPHERTEXTBYTES];
  unsigned char k[crypto_kem_BYTES];
  const unsigned char pk[crypto_kem_PUBLICKEYBYTES];

  crypto_kem_enc(c,k,pk);
  Generates a random session key k[0],...,k[BYTES-1] and
    corresponding ciphertext c[0],...,c[CIPHERTEXTBYTES-1].
    given a public key pk[0],...,pk[PUBLICKEYBYTES-1].
  Always returns 0.
*/
  crypto_kem_enc(SK2CipherText, SK2, SrvNTRUPubKey);

  unsigned t;
  for (t=0; t<32; t++)
    SK1[t] ^= SK2[t];
  xorDeriveKey(SK1, 32, NumJumpsForCommonKey, COMMON_HOHHA_XOR_KEY_BODY_LEN, CommonHohhaKey);

  // We obtained common hohha key
  // We use common hohha key for only one purpose: Enrypting session key
  // Here, we encrypt session key with common key obtained via X25519 and NTRU public/private key pairs
  const unsigned SessionKeyBufLen = xorComputeKeyBufLen(xorGetKeyBodyLen(HohhaSessionKey));
  const unsigned DataAlignment = 16;
  const unsigned EncryptedSessionKeyLen = xorGetExactEncryptedPacketSize(SessionKeyBufLen, DataAlignment);
  uint8_t EncryptedSessionKeyBuf[EncryptedSessionKeyLen];
  xorEncryptAndSign2(CommonHohhaKey, SessionKeyBufLen, HohhaSessionKey, DataAlignment, (uint8_t *)EncryptedSessionKeyBuf);

  // Finally, we encrypt data with session key
  const unsigned EncryptedPackLen = xorGetExactEncryptedPacketSize(smbGetLen(ReqData), DataAlignment);
  uint8_t EncryptedPackBuf[EncryptedPackLen];
  xorEncryptAndSign2(HohhaSessionKey, smbGetLen(ReqData), (uint8_t *)smbGetBuf(ReqData), DataAlignment, (uint8_t *)EncryptedPackBuf);

  size_t BDLen = BASE64_ENCODED_LEN(EncryptedPackLen)+1;
  char *B64Data = chttpMAlloc(chttp, BDLen);

  base64_encode((const char *)EncryptedPackBuf, EncryptedPackLen, B64Data, &BDLen, 0);
  B64Data[BDLen] = '\0';

#if defined(HCDEBUG)
  /*TMemBuf mb;
  mbInit(&MainThreadMemMgr, &mb, 256, 0);
  mbPrint(&mb, "MyPrvKey: %32A\nMyPubKey: %32A\nOPubKeyX25519: %32A\nShared HohhaKey: %75A\nKey creation result: %d\n",
          ClientX25519KeyPair->PrvKey,
          ClientX25519KeyPair->PubKey,
          SrvX25519PubKey,
          CommonHohhaKey);
  DBGPRINT(DBGLVL_DBG,  "%.*s\n",(int)smbGetLen(&mb), smbGetBuf(&mb));*/
#endif
  chttpAddRequestGetOrPOSTVar(chttp, "$E", FALSE, "2", FALSE); // Custom encryption type CUSTOM_ENCRYPTION_X25519_AND_NTRU_PRIME(2)
  chttpAddRequestGetOrPOSTVarBase64(chttp, "$X", FALSE, ClientX25519KeyPair->PubKey, 32);
  chttpAddRequestGetOrPOSTVarBase64(chttp, "$2", FALSE, SK2CipherText, crypto_kem_CIPHERTEXTBYTES);
  chttpAddRequestGetOrPOSTVar(chttp, "$J", FALSE, NumBuf, FALSE);
  chttpAddRequestGetOrPOSTVar(chttp, "$KID", FALSE, KeyIDStrBuf, FALSE);
  chttpAddRequestGetOrPOSTVarBase64(chttp, "$SK", FALSE, EncryptedSessionKeyBuf, EncryptedSessionKeyLen); // Session key encrypted with pre-shared key as base64 string
  chttpAddRequestGetOrPOSTVar(chttp, "$D", FALSE, B64Data, FALSE);
  //chttpUpgradeToWebSocket(chttp, URIWithoutHost, WebSocketExtensionsToOffer, fncOnRequestCompleted);
}
/**
 * chttpSetCustomEncParamsHohhaPSK is an internal function used to set custom encryption parameters for PSK
 * After having called this function, chttpUpgradeToWebSocket(chttp, URIWithoutHost, WebSocketExtensionsToOffer, fncOnRequestCompleted);
 * @param s TChttp pointer
 * @param SrvKeyID Unique identifier of HohhaPSK on server
 * @param const uint8_t *HohhaPSK Pointer to pre-shared hohha key.
 *        PSK is used only to encrypt session key.
 * @param const uint8_t HohhaSessionKey is the session key.
 *        Everything will be encrypted with this key during session.
 * @param ReqData TMemBuf * Request buffer to be sent to server as $D variable
 */
void chttpSetCustomEncParamsHohhaPSKOld(
  TCHttp *chttp,
  unsigned SrvKeyID,
  const uint8_t *HohhaPSK,
  const uint8_t *HohhaSessionKey,
  TMemBuf *ReqData)
{
  char *KeyIDStrBuf = chttpMAlloc(chttp, 12);
  UInt32ToStr(SrvKeyID, KeyIDStrBuf);

  // First, we encrypt session key with pre-shared key and convert it to base64
  const unsigned DataAlignment = 16;
  const unsigned SessionKeyBufLen = xorComputeKeyBufLen(xorGetKeyBodyLen(HohhaSessionKey));
  const unsigned EncryptedSessionKeyLen = xorGetExactEncryptedPacketSize(SessionKeyBufLen, DataAlignment);
  uint8_t EncryptedSessionKeyBuf[EncryptedSessionKeyLen];
  xorEncryptAndSign2(HohhaPSK, SessionKeyBufLen, HohhaSessionKey, DataAlignment, (uint8_t *)EncryptedSessionKeyBuf);


  const unsigned EncryptedPackLen = xorGetExactEncryptedPacketSize(smbGetLen(ReqData), DataAlignment);
  uint8_t EncryptedPackBuf[EncryptedPackLen];
  xorEncryptAndSign2(HohhaSessionKey, smbGetLen(ReqData), (uint8_t *)smbGetBuf(ReqData), DataAlignment, (uint8_t *)EncryptedPackBuf);

  size_t BDLen = BASE64_ENCODED_LEN(EncryptedPackLen)+1;
  char *B64Data = chttpMAlloc(chttp, BDLen);

  base64_encode((const char *)EncryptedPackBuf, EncryptedPackLen, B64Data, &BDLen, 0);
  B64Data[BDLen] = '\0';

  chttpAddRequestGetOrPOSTVar(chttp, "$E", FALSE, "1", FALSE); // Custom encryption type CUSTOM_ENCRYPTION_HOHHA_PSK(1)
  chttpAddRequestGetOrPOSTVarBase64(chttp, "$SK", FALSE, EncryptedSessionKeyBuf, EncryptedSessionKeyLen); // Session key encrypted with pre-shared key as base64 string
  chttpAddRequestGetOrPOSTVar(chttp, "$KID", FALSE, KeyIDStrBuf, FALSE);
  chttpAddRequestGetOrPOSTVar(chttp, "$D", FALSE, B64Data, FALSE);
}

#endif
