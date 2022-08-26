/***************************************************************************
 *   HTTP Client object definitions
 *   Copyright (C) 2005 by Ismail Kizir                                    *
 ***************************************************************************/

#if !defined(HTTP_CLIENT_H)
#define HTTP_CLIENT_H
#include "A99ATypes.h"
#include <MyMemMgr.h>
#include <mychunkalloc.h>
#include <search.h>
#include <string.h>
#include<sys/socket.h>
#include <errno.h>
#include <mymisc.h>
#include <IOBuffers.h>
#include <mytemplate.h>
#include <mystrings.h>
#include "mime.h"
//#include "FileCache.h"
#include "Multiplexer.h"
#include "httpCommon.h"
#include "KVList.h"
#include "linkedlist.h"
#include "NetTypes.h"
#include "OutgoingConn.h"
#include "HohhaXor.h"
#include "HohhaX25519.h"
#include "crypto_kem.h"
#include "CharSets.h"

#ifdef __cplusplus
extern "C" {
#endif

//define HCDEBUG
// Websock extension constants
// They must be OR'ed each other to 
// Sec-WebSocket-Extensions: NoXORMask header is to suppress xor masking frames
#define WEBSOCK_EXTENSION_NOXORMASK_NUM 1
// Sec-WebSocket-Extensions: LZ4-A99A header enables lz4 compression
#define WEBSOCK_EXTENSION_LZ4_NUM 2
// Sec-WebSocket-Extensions: PlainTCPAfterUpgrade is for plain tcp connection after upgrade
#define WEBSOCK_EXTENSION_PLAIN_TCP 4

// Cookie definition for "client side"
typedef struct
{
  const char *Name;
  const char *Value;
  const char *Domain;
  const char *Path;
  const char *Expires;
  const char *LastPropertyName; // Used internally to remember the last property name we're parsing
  unsigned int Secure;
  unsigned int HttpOnly;
} TClientHTTPCookie;

typedef struct THttpCUplFile THttpCUplFile;

struct THttpCUplFile {
  char *FileName;
  TMemBuf *FileContent;
  THttpCUplFile *Next;
  uint32_t MimeType;
};

typedef struct TCHttp TCHttp;

// TCHTTPfncOnRequestCompleted is called by the TCHttp structure when request is successfully or unsuccessfully completed
// Callee must first check ParserError
// If it's ok, it must check ResponseStatusCode
// The data received will be in LastElementData
// TCHttp *s will be automatically freed after this function has been called
// If, user will not use underlying TOutgoingConn * function anymore, he can call chttpDestroyUnderlyingOConn to destroy outgoing connection
typedef void (*TCHTTPfncOnRequestCompleted)(TCHttp *s);

struct TCHttp
{
#if defined(MULTIPLE_CONCURRENT_MULTIPLEXERS)
  TMultiplexer *mpx;
#endif
  //TOutgoingConn *OConn;
  TIOBuf *io;
  TMemInputBuffer *LastInputChunk;
  uint64_t CurrentChunkNumRead;
  TCHTTPfncOnRequestCompleted fncOnRequestCompleted;
  TfncOnNewCommandOrFrame fncOnNewCommandOrFrame; // After websocket upgrade, it will be needed to set new handler
  const char *Host; // Host: xxx header to be sent with request
  const char *URIWithoutHost; // URI without host part to be sent with GET xxx value
  TSimpleMemBuf *ChunkHeaderAndTrailerData;
  union {
    char *LastVarName;
    TClientHTTPCookie *LastCookie;
  };
  //char *Path;
  TMemBuf *ReqBody; // For content-type mime types other than MIME_APPLICATION_X_WWW_FORM_URLENCODED or file uploads
  char *MultipartBoundaryStr;
  TKVHead RequestGetOrPOSTVars, ResponseCookies; // POST Vars. GET vars must be given with uri!
  TKVHead RequestHeaders, ResponseHeaders;
  THttpCUplFile *FilesToUpload;
  TCBFncParam ExtraData;
  TSimpleMemBuf *LastElementData;
  uint64_t CurrentChunkLen;
  uint64_t ResponseContentLength;
  TChunkInfo ChunkInfo;
  int16_t LastCharRead; // It must be at least 10 bits!
  uint16_t State;
  uint16_t ParserError;
  uint16_t RequestContentType;
  uint16_t ResponseStatusCode;
  uint8_t ChunkReadState; // Read state for chunk encoded transfer 0->Non chunked response; 1->Reading chunk header; 2->Reading chunk body
  uint8_t HttpResponseVersion;
  uint8_t KeepAlive;
  uint8_t Secure; // Not implemented yet. For future use
  uint8_t HeaderParseCompleted; // We completed processing the header part. Now, we are in body
  uint8_t ConsumedAllData;
  uint8_t RequestMethod;
  uint8_t FreeThisStructure;
};
static inline void chttpSetRequestContentType(TCHttp *chttp, unsigned T) { chttp->RequestContentType = T; }
TSocketProfileTCP *chttpGetDefaultSockProfile(void);
/**
 * chttpCreateOutgoingConn creates a new TOutgoingConn structure with an appropriate socket profile to be used as TCHttp's outgoing connection object
 * @param mpx Multiplexer
 * @param isSecure 1 if it will be an SSL(https or wss) connection; 0 if not! USE ONLY 1 or 0 values! It's not a boolean
 * @param TCBFncParam ExtraData is the parameters to pass to OutgoingConn object to be created
 * @return new TOutgoingConn object pointer
 */
TOutgoingConn *chttpCreateOutgoingConn(TMultiplexer *mpx, uint8_t isSecure, TCBFncParam ExtraData);

/**
 * chttpInit initializes a client http object with an already connected io
 * Default method is
 * @param s Previously allocated TCHttp pointer
 * @param io Already connected TIOBuf pointer
 * @param Host Host: xxx header to be sent with http requests
 * @return
 */
int32_t chttpInit(TCHttp *s, TIOBuf *io, const char *Host, TCBFncParam ExtraData);

/**
 * chttpInitNew Allocates a new TCHttp structure from io's underlying memory manager
 *   and initializes a client http object with an already connected io
 * @param io Already connected TIOBuf pointer
 * @param Host Host: xxx header to be sent with http requests
 * @return
 */
TCHttp *chttpInitNew(TIOBuf *io, const char *Host, TCBFncParam ExtraData);

#if defined(MULTIPLE_CONCURRENT_MULTIPLEXERS)
static inline TMultiplexer *chttpGetMultiplexer(TCHttp *s) { return s->mpx; }
#else
static inline TMultiplexer *chttpGetMultiplexer(TCHttp *s) { return mpxDefault; }
#endif

/**
 * chttpAddAuthenticationCredentials adds basic authentication credentials to request 
 *   as described in rfc2617: https://tools.ietf.org/html/rfc2617
 * @param s TCHttp *
 * @param UserName const char *
 * @param Password 
 * @return TRUE if Authorization header successfully added. FALSE if parameters are invalid
 */ 
TBool chttpAddAuthenticationCredentials(TCHttp *s, const char *UserName, const char *Password);
static inline void chttpSetReqBody(TCHttp *s, TMemBuf *b) { s->ReqBody = b; }
TBool chttpAddFileToUpload(TCHttp *s, const char *FileFullPath, uint32_t MimeType);
const char *chttpResponseCodeStrForm(uint32_t HTTPResponseCode);
static inline uint32_t chttpGetState(TCHttp *s) { return s->State; }
static inline void chttpSetState(TCHttp *s, uint32_t State) { s->State = State; }
static inline int32_t chttpGetLastRawCharRead(TCHttp *s) {return s->LastCharRead;}
static inline uint32_t chttpGetResponseProtocol(TCHttp *s) { return s->HttpResponseVersion; }
void chttpDestroyUploadedFiles(TCHttp *s);
//int32_t chttpDoWebSocketUpgradeHandShake(TCHttp *s, const unsigned char *HandshakeResultMD5);
int32_t chttpGetRange(TCHttp *s, int64_t *Start, int64_t *NumBytes);
void chttpAddRequestGetOrPOSTVar(TCHttp *s,const char *K, uint32_t MallocForKey, const char *V, uint32_t MallocForValue);
void chttpAddRequestGetOrPOSTVarInt64 (TCHttp *s, const char *K, uint32_t MAllocForKey, int64_t Num);
void chttpAddRequestGetOrPOSTVarUInt64 (TCHttp *s, const char *K, uint32_t MAllocForKey, int64_t Num);
/**
 * chttpAddRequestGetOrPOSTVarBase64 adds a request var as a base64 encoded string
 * @param s TCHttp *
 * @param K Key name
 * @param MallocForKey TRUE if memory will be allocated
 * @param V Value buffer pointer
 * @param VLen Length of value buffer.
 */
void chttpAddRequestGetOrPOSTVarBase64(TCHttp *s, const char *K, uint32_t MallocForKey, const void *V, const uint32_t VLen);
void chttpAddRequestGetOrPOSTVarBin(TCHttp *s,const char *K, const uint32_t MallocForKey, const char *V, const uint32_t ValueLen, const uint32_t MallocForValue);
void chttpAddRequestHeader(TCHttp *s,const char *K, const uint32_t MallocForKey, const char *V, const uint32_t MallocForValue);
static inline const char *chttpGetRequestHeader (TCHttp *s, const char *K) { return kvGetStrValueWithStrKey(&s->RequestHeaders, K); }
static inline const char *chttpGetResponseHeader (TCHttp *s, const char *K) { return kvGetStrValueWithStrKey(&s->ResponseHeaders, K); }
static inline const TKeyValue *chttpGetResponseHeaderKV (TCHttp *s, const char *K) { return kvGetWithStrKey(&s->ResponseHeaders, K); }

void chttpAddResponseHeader(TCHttp *s, const char *K, uint32_t MallocForKey, const char *V, uint32_t MallocForValue);
void chttpAddResponseHeaderInt64 (TCHttp *s, const char *K, uint32_t MallocForKey, int64_t Num);

static inline unsigned chttpGetResponseStatusCode (TCHttp *s) { return s->ResponseStatusCode; }

const char *chttpGetConnectionStateStr(uint32_t ConnectionState);
//static inline const char *chttpGetRequestAcceptEncoding(TCHttp *s) { return chttpGetRequestHeader(s, "Accept-Encoding"); }


static inline void chttpSetRequestMethod(TCHttp *s, unsigned int Method) { s->RequestMethod = Method; }
static inline uint32_t chttpGetRequestMethod(TCHttp *s) { return s->RequestMethod; }

/**
 * @brief chttpExtractCharSet extracts character set from Content-Type header
 * @param s TCHttp *
 * @return TCharSet
 */
TCharSet chttpExtractCharSet(TCHttp *s);

static inline char *chttpMAlloc(TCHttp *s, size_t size) { return (char *)AllocChunk(&s->ChunkInfo, size); }
static inline char *chttpStrDup(TCHttp *s, const char *str) { return (char *)ChunkStrDup(&s->ChunkInfo, str); }
static inline char *chttpStrDupLen(TCHttp *s, const char *str, size_t Len) { return (char *)ChunkStrDupLen(&s->ChunkInfo, str, Len); }
const char *chttpFetchRequestGetOrPostVarStr(TCHttp *s, const char *varname, char *buf, uint32_t maxlen);
static inline const char *chttpFetchRequestGetOrPostVar(TCHttp *s, const char *Varname) { return kvGetStrValueWithStrKey(&s->RequestGetOrPOSTVars, Varname); }
void chttpPrintResponseHeaders(TCHttp *s);
static inline uint64_t chttpGetResponseLen(TCHttp *s) { return smbGetLen(s->LastElementData); }
static inline const char *chttpGetResponseBody(TCHttp *s) { return (const char *)smbGetBuf(s->LastElementData); }
static inline TSimpleMemBuf *chttpGetResponse(TCHttp *s) { return s->LastElementData; }
/**
 * chttpSendRequest sends a request to server
 * @param s TCHttp *
 * @param URIWithoutHost URI to be requested from server. But without Host:Port part
 * @param EncParams TCustomEncParamsForClient * Custom encryption parameters, any custom encryption will be used. Or NULL
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
  TBool ForceMultipartEncoding);

/**
 * chttpSendRequest sends a custom encrypted request to server
 * @param s TCHttp *
 * @param URIWithoutHost URI to be requested from server. But without Host:Port part
 * @param EncParams TCustomEncParamsForClient * Custom encryption parameters, any custom encryption will be used. Or NULL
 * @params DataToSendInEcryptedForm TSimpleMemBuf *
 *         Login parameters buffer to be encrypted and to be sent to server
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
  TBool ForceMultipartEncoding);

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
  TCHTTPfncOnRequestCompleted fncOnRequestCompleted);

void chttpUpgradeToWebSocketWithCustomEnc(TCHttp *s,
  const char *URIWithoutHost,
  TCustomEncParamsForClient *EncParams,
  TSimpleMemBuf *LoginParamsAsPlainText,
  uint64_t WebSocketExtensionsToOffer,
  TCHTTPfncOnRequestCompleted fncOnRequestCompleted);

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
TIOBuf *chttpConvertUnderlyingIOToWebsocketProfile(TCHttp *s, TfncOnNewCommandOrFrame fncOnNewCommandOrFrame, TfncIOBufGetHohhaEncryptionKey fncIOBufGetHohhaEncryptionKey, unsigned int TimeoutInMs);


//void chttpDestroyUnderlyingIO(TCHttp *s);

/**
 * chttpDetachUnderlyingIO cuts the relationship between TCHttp *s and underlying TIOBuf and returns io 
 * When an io is detached from TCHttp, it survives after TCHttp is destroyed!
 * @param s TCHttp *
 * @return Underlying, detached io TIOBuf *
 */
TIOBuf *chttpDetachUnderlyingIO(TCHttp *s);

void chttpDestroyAndFree(TCHttp *chttp); 

#define chttpForEachResponseHeaderFIFO(CHttp, KV) kvForEachFIFO(&CHttp->ResponseHeaders, KV)
#define chttpForEachResponseHeaderLIFO(CHttp, KV) kvForEachLIFO(&CHttp->ResponseHeaders, KV)


void chttpDestroyUnderlyingIO(TCHttp *s);

extern TSocketProfileTCP HTTP_CLIENT_DEFAULT_SOCKET_PROFILE;

#ifdef __cplusplus
}
#endif

#endif
