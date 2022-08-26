#include "Config.h"
#include "Multiplexer.h"
#include "httpCommon.h"
#include "httpClient.h"
#include "DemoHTTPClient.h"
#include "OutgoingConn.h"
#include "IOBuffers.h"
#include "http.h"
#include "IOBufCache.h"

#define DONT_USE_IO_CACHE
static void fncOnCHTTPRequestToNewspaperCompleted(TCHttp *chttp);

#define HOST  "https://www.milenio.com" //"https://clarin.com"  // "https://www.aa.com.tr"
#define CRAWLER_USER_AGENT "PiplBot"

void ParseRobotsTxtFile(const char *Txt, unsigned TxtLen)
{
  TBool ConcernsUs=FALSE;
  const uint8_t
    *sp = (uint8_t *)Txt,
    *UpTo = sp + TxtLen,
    *ValPtr = NULL,
    *LineStart=sp;
  unsigned KeyLen, ValLen;
puts("\n\n----------\n");
  while (sp < UpTo)
  {
    if (*sp == ':' && !KeyLen && *LineStart != '#')
    {
      if (sp < (UpTo-1) && *(sp+1) == ' ')
      {
        KeyLen = sp - LineStart;
        sp++;
        ValPtr = sp+1;
      }
    }
    else if (*sp == '\n')
    {
      if (*LineStart != '#' && KeyLen)
      {
        ValLen = (unsigned)(sp-ValPtr);
        if (KeyLen == LEN_CONST("User-agent") &&
            strncasecmp((const char *)LineStart, "user-agent", LEN_CONST("User-agent")) == 0)
        {
          ConcernsUs = (
            (*ValPtr == '*') ||
            (ValLen == strlen(CRAWLER_USER_AGENT) &&
             strncasecmp((const char *)ValPtr, CRAWLER_USER_AGENT, strlen(CRAWLER_USER_AGENT)) == 0
            )
          );
        }
        else if (ConcernsUs)
        {
          if (KeyLen == LEN_CONST("sitemap") &&
              strncasecmp((const char *)LineStart, "sitemap", LEN_CONST("sitemap")) == 0)
          {
            DBGPRINT(DBGLVL_INFO, "Sitemap: [%.*s]\n", (int)ValLen, ValPtr);
          }
          else if (KeyLen == LEN_CONST("disallow") &&
                   strncasecmp((const char *)LineStart, "disallow", LEN_CONST("disallow")) == 0)
          {
            DBGPRINT(DBGLVL_INFO, "Disallow: [%.*s]\n", (int)ValLen, ValPtr);
          }
          else DBGPRINT(DBGLVL_INFO, "Key: [%.*s] Val: [%.*s]\n",
                 (int)KeyLen, (const char *)LineStart,
                 (int)ValLen, ValPtr);
        }
      }
      if (sp < (UpTo-1) && *(sp+1) == '\r')
        sp++;
      LineStart = sp+1;
      KeyLen = 0;
    }
    sp++;
  }
}
//#define DONT_USE_IO_CACHE
#if !defined(DONT_USE_IO_CACHE)
TIOBufCacheStruct ioc;
static void fncOnConnReady(TIOBuf *io, TCBFncParam CBParam)
{
  DBGPRINT(DBGLVL_DBG, "Status: %s\n", (io ? "CONNECTED" : "NOT CONNECTED!"));
  
  if (!io)
  { // Outgoing connection couldn't be created!!
    DBGPRINT(DBGLVL_ERR, "Error: %s", "Outgoing connection couldn't be created");
    
    return;
  }

  TCHttp *chttp = chttpInitNew(io, HOST, (TCBFncParam)((void *)NULL));
  //chttpSetRequestMethod(s, HTTP_METHOD_GET); GET IS THE DEFAULT METHO


  chttpSendRequest(chttp,
                   CBParam.DataAsUInt64 == 1 ? "/robots.txt" : "/rss/mundo",
                   fncOnCHTTPRequestToNewspaperCompleted,
                   FALSE);
}
#endif

/**
 * fncOnCHTTPRequestToNewspaperCompleted is called by chttpSendRequest function on either successful or unsuccessful operation
 * Check chttp->ParserError first. If it is 0, then there is no parse error, and request has been successfully sent.
 * Then, you can check for chttpGetResponseStatusCode(chttp) == 200
 * After this function, chttp will be automatically freed
 * If you will not need underlying outgoing connection anymore, you can call chttpDestroyUnderlyingOConn(TCHttp *s) function
 * @param chttp
 */
static void fncOnCHTTPRequestToNewspaperCompleted(TCHttp *chttp)
{
  unsigned long long int ResponseLen = (unsigned long long int)smbGetLen(chttp->LastElementData);
  DBGPRINT(DBGLVL_INFO, "fncOnCHTTPRequestCompleted CALLED for %s ParserError: %u Response Status Code: %u ResponseLen: %llu\n",
          chttp->URIWithoutHost,
          (unsigned)chttp->ParserError,
          chttpGetResponseStatusCode(chttp),
          ResponseLen);
  
  /*if (mbGetLen(chttp->LastElementData) > 60)
    sprintf((char *)mbGetBody(chttp->LastElementData) + 40, "...");*/
  if (ResponseLen)
  {
    DBGPRINT(DBGLVL_INFO, "Content: %.*s\n\n",
           (int)smbGetLen(chttp->LastElementData),
           (const char *)smbGetBuf(chttp->LastElementData));
    ParseRobotsTxtFile(
      (const char *)smbGetBuf(chttp->LastElementData),
      smbGetLen(chttp->LastElementData)
    );
  } else dbglogSend3("Response body is empty!\n");

return;

  // For an example to re-use the io object for another http client request, comment out return statement
  if (strcmp(chttp->URIWithoutHost, "/en/rss/default?cat=world") == 0)
  {
    // We must follow exactly the following steps to re-use the io object for another chttp object
    // We must first call chttpDetachUnderlyingIO(chttp) before re-using it for another chttp object
    TIOBuf *io = chttpDetachUnderlyingIO(chttp);
#if !defined(DONT_USE_IO_CACHE)
    iocPush(&ioc, io, FALSE);
    iocPop(&ioc, HOST, chttpGetDefaultSockProfile(), NULL, (TCBFncParam)((uint64_t)2), fncOnConnReady);
#else
    TCHttp *chttpNew = chttpInitNew(io, chttp->Host, CB_FNC_PRM_NULL);
    chttpSendRequest(chttpNew, "/rss/tecnologia", fncOnCHTTPRequestToNewspaperCompleted, FALSE);
#endif
  } // else io will be automatically destroyed!
}

#if defined(DONT_USE_IO_CACHE)
/**
 * fncOnConnectToNewspaper will be called by the OutgoingConn object when an outgoing connect to the newspaper is successful
 * Its prototype is defined in as:
 * typedef void (*TOutgoingConnfncOnConnect)(TOutgoingConn *, int ConnectionStatus);
 * If Status is 0, then connection is successfull. Else, it means we couldn't connect
 */
static void fncOnConnectToNewspaper(TOutgoingConn *s, int ConnectionStatus)
{
  DBGPRINT(DBGLVL_INFO, "ConnectionStatus: %d\n", ConnectionStatus);
  
  if (ConnectionStatus)
  {
    printf("Could not connect to server!\n\n");
    
    return;
  }
  TParsedURI *A = ocGetActualParsedURI(s);
  assert(A != NULL);
  TCBFncParam ExtraData;
  TCHttp *chttp = chttpInitNew(s->io, A->Host, CB_FNC_PRM_NULL); // Use A->Host
  //chttpSetRequestMethod(s, HTTP_METHOD_GET); GET IS THE DEFAULT METHO

  ocDetachUnderlyingIO(s);
  chttpSendRequest(
    chttp,
    "/robots.txt",
    fncOnCHTTPRequestToNewspaperCompleted,
    FALSE);
}
#endif


// --------------------- END: CUSTOM ENCRYPTED HTTP DEMO1: PSK -----------------------------
void RunHTTPSClientDemo(TMultiplexer *mpx)
{
#if defined(DONT_USE_IO_CACHE)
  TOutgoingConn *OConn = chttpCreateOutgoingConn(mpx, TRUE, CB_FNC_PRM_NULL);

  ocConnect(OConn, HOST, fncOnConnectToNewspaper);
#else
  iocInit(mpx, &ioc, 3, 7, 2);
  iocPop(&ioc, HOST, chttpGetDefaultSockProfile(), NULL, (TCBFncParam)((uint64_t)1), fncOnConnReady);
#endif
}
