/*
 * Copyright (c) 2010 Apple Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _CC_CryptorSPI_H_
#define _CC_CryptorSPI_H_

#include <sys/types.h>
#include <stdint.h>

#include <string.h>
#include <limits.h>
#include <stdlib.h>

#if defined(_MSC_VER)
#include <availability.h>
#else
#include <os/availability.h>
#endif

#include <CommonCrypto/CommonCryptoError.h>
#include "CommonCryptoErrorSPI.h"
#include <CommonCrypto/CommonCryptor.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
     Private Modes
 */
enum {
    kCCModeXTS        = 8,
    kCCModeGCM        = 11,
    kCCModeCCM        = 12,
};

/*
    Private Cryptor direction (op)
 */
enum {
    kCCBoth        = 3,
};

/*
    Block mode encrypt and decrypt interfaces for IV tweaked blocks (XTS and CBC)
*/

CCCryptorStatus CCCryptorEncryptDataBlock(
    CCCryptorRef    cryptorRef,
    const void      *iv,
    const void      *dataIn,
    size_t          dataInLength,
    void            *dataOut)
API_AVAILABLE(macos(10.7), ios(5.0));


CCCryptorStatus CCCryptorDecryptDataBlock(
    CCCryptorRef cryptorRef,
    const void *iv,
    const void *dataIn,
    size_t dataInLength,
    void *dataOut)
API_AVAILABLE(macos(10.7), ios(5.0));

/*
     This finalizes the GCM state gcm.

     On encryption, the computed tag is returned in tagOut.

     On decryption, the provided tag is securly compared to the expected tag, and
     error is returned if the tags do not match. The tag buffer contectnt is not modified on decryption.
     is not updated on decryption.
*/
CCCryptorStatus
CCCryptorGCMFinalize(CCCryptorRef cryptorRef, void   *tag, size_t tagLength)
API_AVAILABLE(macos(10.13), ios(11.0));

/*
    This will reset the GCM CCCryptorRef to the state that CCCryptorCreateWithMode()
    left it. The user would then call CCCryptorGCMAddIV(), CCCryptorGCMaddAAD(), etc.
*/
CCCryptorStatus
CCCryptorGCMReset(CCCryptorRef cryptorRef)
API_AVAILABLE(macos(10.8), ios(5.0));

enum {
    /*
        Initialization vector - cryptor input parameter, typically
        needs to have the same length as block size, but in some cases
        (GCM) it can be arbitrarily long and even might be called
        multiple times.
    */
    kCCParameterIV,

    /*
        Authentication data - cryptor input parameter, input for
        authenticating encryption modes like GCM.  If supported, can
        be called multiple times before encryption starts.
    */
    kCCParameterAuthData,

    /*
        Mac Size - cryptor input parameter, input for
        authenticating encryption modes like CCM. Specifies the size of
        the AuthTag the algorithm is expected to produce.
    */
    kCCMacSize,

    /*
        Data Size - cryptor input parameter, input for
        authenticating encryption modes like CCM. Specifies the amount of
        data the algorithm is expected to process.
    */
    kCCDataSize,

    /*
        Authentication tag - cryptor output parameter, output from
        authenticating encryption modes like GCM.  If supported,
        should be retrieved after the encryption finishes.
    */
    kCCParameterAuthTag,
};
typedef uint32_t CCParameter;

/*
    Sets or adds some other cryptor input parameter.  According to the
    cryptor type and state, parameter can be either accepted or
    refused with kCCUnimplemented (when given parameter is not
    supported for this type of cryptor at all) or kCCParamError (bad
    data length or format) or kCCCallSequenceError (bad sequence of
    calls when using GCM or CCM).
*/
CCCryptorStatus
CCCryptorAddParameter(CCCryptorRef cryptorRef, CCParameter parameter, const void *data, size_t dataSize);

/*
    Gets value of output cryptor parameter.  According to the cryptor
    type state, the request can be either accepted or refused with
    kCCUnimplemented (when given parameteris not supported for this
    type of cryptor) or kCCBufferTooSmall (in this case, *dataSize
    argument is set to the requested size of data).
*/
CCCryptorStatus
CCCryptorGetParameter(CCCryptorRef cryptorRef, CCParameter parameter, void *data, size_t *dataSize);

#ifdef __cplusplus
}
#endif

#endif /* _CC_CryptorSPI_H_ */
