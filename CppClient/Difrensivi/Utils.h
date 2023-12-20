#pragma once

#include "RSAWrapper.h"
#include "AESWrapper.h"
#include <iostream>
#include <array>

#define UNSIGNED(n) (n & 0xffffffff)
/////////////kind bytes
//Asymmetric encryption key length:
#define CHUNK_SIZE  (1024)
#define UUID_SIZE (16)
#define MAX_USERNAME (255)
#define MAX_FILENAME (255)
#define PUBUBLIC_KEY_SIZE (RSAPublicWrapper::KEYSIZE)// RSA 1024 bit X509 format
#define CONTENT_SIZE (4)
#define HEADER_SIZE (23)
#define HEADER_SIZE_RESPONSE (7)
#define BLOCK_SIZE (16) 
#define PUBUBLIC_KEY_SIZE (160) 	
 // AES-CBC 128 bit
#define SYMMETRIC_KEY_SIZE (AESWrapper::DEFAULT_KEY_LENGTH) 
#define CRC_SIZE (4)
//Verify the file up to 3 times
#define SEND_TIMES (3)
//Files name
#define TRANSFER_INFO_FILE ("transfer.info")
#define ME_INFO_FILE ("me.info")
#define PRIVATE_KEY_FILE ("priv.key")
//Server version
#define SERVER_VERSION (3)
//Message code
#define REGISTER_REQUEST (1025)
#define SEND_PUBLIC_KEY (1026)
#define RELOGIN_REQUEST (1027)
#define SEND_FILE (1028)
#define FILE_CRC_OK (1029)
#define FILE_CRC_FAILED (1030)
#define FILE_CRC_FAILED_FOUR_TIMES (1031)
//response code
/* 
Registration was successful If a user is saved in memory, it will return a success answer
*/
#define REGISTER_SUCCESS (2100)
/**
 *  Registration  failed ,If a user is not saved in memory, it will return a success answer 
 */
#define REGISTER_FAILED (2101)

//#public key received sending AES key
#define RECEIVE_AES_KEY (2102)

//#File received OK CRC
#define RECEIVE_CRC_OK (2103)

//Message confirmation, thank you
#define GOT_MESSAGE_SUCCESSFULLY (2104)

//Confirms relogin message request 
#define CONFIRM_RELOGIN_REQUEST (2105)

//#Login request rejected
#define REJECT_RELOGIN_REQUEST (2106)


struct ResponseHeader {
	uint8_t  serverVersion = 0;
	uint16_t statusCode = 0;
	uint32_t payloadSize = 0;
};
