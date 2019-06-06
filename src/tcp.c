//! @addtogroup TCPServerSocket
//! @brief Intialise TCP Server Socket
//! @{
//!
//****************************************************************************/
//! @file tcp.c
//! @brief TCP Server Socket
//! @author Savindra Kumar(savindran1989@gmail.com)
//! @bug No known bugs.
//!
//****************************************************************************/
//****************************************************************************/
//                           Includes
//****************************************************************************/
//standard header files
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
//wolfSSL includes
#include "wolfssl/ssl.h"
#include <mbap_conf.h>

//****************************************************************************/
//                           Defines and typedefs
//****************************************************************************/
#define BUFF_SIZE_IN_BYTES   256u
#define PORT_NUMBER          502u
#define TCP_SOCKET_ERROR     -1
//****************************************************************************/
//                           external variables
//****************************************************************************/

//****************************************************************************/
//                           Local variables
//****************************************************************************/
//The wolfSSL context for the server
static WOLFSSL_CTX* xWolfSSL_ServerContext = NULL;

//****************************************************************************/
//                           Local Functions
//****************************************************************************/
//Prepare the wolfSSL library for use.
static void InitiWolfSSL (void);

//****************************************************************************/
//                    G L O B A L  F U N C T I O N S
//****************************************************************************/
//
//! @brief Initalise TCP Server Socket and Call Modbus Application
//! @param[in]  None
//! @param[out] None
//! @return     None
//
void tcp_Init(void)
{
    WOLFSSL           *xWolfSSL_Object                 = NULL;
    uint8_t            pucQuery[BUFF_SIZE_IN_BYTES]    = {0};
    uint8_t            pucResponse[BUFF_SIZE_IN_BYTES] = {0};
    int16_t            sResult                         = 0;
    socklen_t          len                             = 0;
    int                sock_desc                       = 0;
    int                temp_sock_desc                  = 0;
    struct sockaddr_in server;
	struct sockaddr_in client;

    memset(&server, 0, sizeof(server));
    memset(&client, 0, sizeof(client));

    // Perform the initialisation necessary before wolfSSL can be used
    InitiWolfSSL();

    sock_desc = socket(AF_INET, SOCK_STREAM, 0);

    if (TCP_SOCKET_ERROR == sock_desc)
    {
        printf("Error in socket creation");
        return;
    }

    server.sin_family      = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port        = htons(PORT_NUMBER);

    sResult = bind(sock_desc, (struct sockaddr*)&server, sizeof(server));

    if (TCP_SOCKET_ERROR == sResult)
    {
        printf("Error in binding");
        return;
    }

    sResult = listen(sock_desc, 20);

    if (TCP_SOCKET_ERROR == sResult)
    {
        printf("Error in listening");
        return;
    }

    len = sizeof(client);

    printf("Starting:\r\n");

    CLIENT_REQUEST:
    while ( (temp_sock_desc = accept(sock_desc, (struct sockaddr*)&client, &len)) )
    {
        printf("\nClient connected\n");

        // A connection has been accepted by the server.  Create a
        //wolfSSL object for use with the newly connected socket
        xWolfSSL_Object = NULL;
        xWolfSSL_Object = wolfSSL_new( xWolfSSL_ServerContext );

        if (xWolfSSL_Object != NULL)
        {
            // Associate the created wolfSSL object with the connected socket
            sResult = wolfSSL_set_fd( xWolfSSL_Object, temp_sock_desc );

            if (SSL_SUCCESS != sResult)
            {
                printf("fd error\r\n");
            }

            while (1)
            {
                uint16_t usResponseLength = 0;

                sResult = wolfSSL_read( xWolfSSL_Object, pucQuery, sizeof( pucQuery ) );

                if (0 == sResult)
                {
                    printf("\nConnection closed\n");
                    // The connection was closed, close the socket and free the wolfSSL object
                    close(temp_sock_desc);
                    wolfSSL_free(xWolfSSL_Object);
                    break;
                }
                else if (sResult < 0)
                {
                    printf("\nConnection reset\n");
                    // The connection was closed, close the socket and free the wolfSSL object
                    close(temp_sock_desc);
                    wolfSSL_free(xWolfSSL_Object);
                    break;
                }
                else
                {
                    //read successfully
                }

                usResponseLength = mbap_ProcessRequest(pucQuery, sResult, pucResponse);

                if (0 != usResponseLength)
                {
                    sResult = wolfSSL_write(xWolfSSL_Object, pucResponse, usResponseLength);

                    if (sResult < 0)
                    {
                        printf("\nsend failed\n");
                    }
                }//end if
            }//end while
        }//end if
    }//end while


    if (temp_sock_desc < 0)
    {
        printf("accpet failed");
        goto CLIENT_REQUEST;
    }

    exit(0);
}//end TcpInit

//****************************************************************************/
//                           L O C A L  F U N C T I O N S
//****************************************************************************/
static void InitiWolfSSL( void )
{
    int32_t iReturn;

    #ifdef DEBUG_WOLFSSL
    {
        wolfSSL_Debugging_ON();
    }
    #endif

    // Initialise wolfSSL.  This must be done before any other wolfSSL functions
    //are called
    wolfSSL_Init();

    // Attempt to create a context that uses the TLS 1.2 server protocol.
    xWolfSSL_ServerContext = wolfSSL_CTX_new( wolfTLSv1_2_server_method() );

    if (NULL != xWolfSSL_ServerContext)
    {
        // Load the CA certificate.  Real applications should ensure that
        //wolfSSL_CTX_load_verify_locations() returns SSL_SUCCESS before
        //proceeding.
        iReturn = wolfSSL_CTX_load_verify_locations(xWolfSSL_ServerContext, "ca-cert.pem", 0);

        if (SSL_SUCCESS != iReturn)
        {
            printf("ca certificate error\r\n");
        }

        iReturn = wolfSSL_CTX_use_certificate_file(xWolfSSL_ServerContext, "server-cert.pem", SSL_FILETYPE_PEM);

        if (SSL_SUCCESS != iReturn)
        {
            printf("server certificate error\r\n");
        }

        iReturn = wolfSSL_CTX_use_PrivateKey_file(xWolfSSL_ServerContext, "server-key.pem", SSL_FILETYPE_PEM);

        if (SSL_SUCCESS != iReturn)
        {
            printf("server key error\r\n");
        }
    }//end if
}//end InitiWolfSSL

//****************************************************************************/
//                             End of file
//****************************************************************************/
/** @}*/
