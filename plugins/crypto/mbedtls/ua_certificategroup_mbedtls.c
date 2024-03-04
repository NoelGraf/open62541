/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2019 (c) Kalycito Infotech Private Limited
 *    Copyright 2019 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2024 (c) Fraunhofer IOSB (Author: Noel Graf)
 */

#include <open62541/util.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/log_stdout.h>

#ifdef UA_ENABLE_ENCRYPTION_MBEDTLS

#include "securitypolicy_mbedtls_common.h"
#include "../ua_certificategroup_common.h"

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>

#include <inttypes.h>

#define REMOTECERTIFICATETRUSTED 1
#define ISSUERKNOWN              2
#define DUALPARENT               3
#define PARENTFOUND              4

/* Find binary substring. Taken and adjusted from
 * http://tungchingkai.blogspot.com/2011/07/binary-strstr.html */

static const unsigned char *
bstrchr(const unsigned char *s, const unsigned char ch, size_t l) {
    /* find first occurrence of c in char s[] for length l*/
    for(; l > 0; ++s, --l) {
        if(*s == ch)
            return s;
    }
    return NULL;
}

static const unsigned char *
UA_Bstrstr(const unsigned char *s1, size_t l1, const unsigned char *s2, size_t l2) {
    /* find first occurrence of s2[] in s1[] for length l1*/
    const unsigned char *ss1 = s1;
    const unsigned char *ss2 = s2;
    /* handle special case */
    if(l1 == 0)
        return (NULL);
    if(l2 == 0)
        return s1;

    /* match prefix */
    for (; (s1 = bstrchr(s1, *s2, (uintptr_t)ss1-(uintptr_t)s1+(uintptr_t)l1)) != NULL &&
           (uintptr_t)ss1-(uintptr_t)s1+(uintptr_t)l1 != 0; ++s1) {

        /* match rest of prefix */
        const unsigned char *sc1, *sc2;
        for (sc1 = s1, sc2 = s2; ;)
            if (++sc2 >= ss2+l2)
                return s1;
            else if (*++sc1 != *sc2)
                break;
    }
    return NULL;
}

typedef struct {
    mbedtls_x509_crt trustedCertificates;
    mbedtls_x509_crt trustedIssuers;
    mbedtls_x509_crl trustedCertificateCrls;
    mbedtls_x509_crl trustedIssuerCrls;
} CertInfo;

static void
CertInfo_clear(CertInfo* certInfo){
    mbedtls_x509_crt_free(&certInfo->trustedCertificates);
    mbedtls_x509_crt_free(&certInfo->trustedIssuers);
    mbedtls_x509_crl_free(&certInfo->trustedCertificateCrls);
    mbedtls_x509_crl_free(&certInfo->trustedIssuerCrls);
}

static void
CertInfo_init(CertInfo* certInfo){
    mbedtls_x509_crt_init(&certInfo->trustedCertificates);
    mbedtls_x509_crt_init(&certInfo->trustedIssuers);
    mbedtls_x509_crl_init(&certInfo->trustedCertificateCrls);
    mbedtls_x509_crl_init(&certInfo->trustedIssuerCrls);
}

#include <dirent.h>

static UA_StatusCode
reloadCertificates(CertInfo *ci, UA_CertificateGroup *certGroup,
                   const UA_ByteString *issuerCertificates, size_t issuerCertificatesSize) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    int err = 0;

    UA_ByteString data;
    UA_ByteString_init(&data);

    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    retval = certGroup->getTrustList(certGroup, &trustList);
    if(!UA_StatusCode_isGood(retval))
        goto error;

    /* Additional issuer certificates to verify the certificate */
    if(issuerCertificates != NULL && issuerCertificatesSize > 0) {
        for(size_t i = 0; i < issuerCertificatesSize; ++i) {
            data = UA_mbedTLS_CopyDataFormatAware(&issuerCertificates[i]);
            err = mbedtls_x509_crt_parse(&ci->trustedIssuers,
                                         data.data,
                                         data.length);
            UA_ByteString_clear(&data);
            if(err)
                goto error;
        }
    }
    for(size_t i = 0; i < trustList.trustedCertificatesSize; ++i) {
        data = UA_mbedTLS_CopyDataFormatAware(&trustList.trustedCertificates[i]);
        err = mbedtls_x509_crt_parse(&ci->trustedCertificates,
                                     data.data,
                                     data.length);
        UA_ByteString_clear(&data);
        if(err)
            goto error;
    }
    for(size_t i = 0; i < trustList.issuerCertificatesSize; ++i) {
        data = UA_mbedTLS_CopyDataFormatAware(&trustList.issuerCertificates[i]);
        err = mbedtls_x509_crt_parse(&ci->trustedIssuers,
                                     data.data,
                                     data.length);
        UA_ByteString_clear(&data);
        if(err)
            goto error;
    }
    for(size_t i = 0; i < trustList.trustedCrlsSize; i++) {
        data = UA_mbedTLS_CopyDataFormatAware(&trustList.trustedCrls[i]);
        err = mbedtls_x509_crl_parse(&ci->trustedCertificateCrls,
                                     data.data,
                                     data.length);
        UA_ByteString_clear(&data);
        if(err)
            goto error;
    }
    for(size_t i = 0; i < trustList.issuerCrlsSize; i++) {
        data = UA_mbedTLS_CopyDataFormatAware(&trustList.issuerCrls[i]);
        err = mbedtls_x509_crl_parse(&ci->trustedIssuerCrls,
                                     data.data,
                                     data.length);
        UA_ByteString_clear(&data);
        if(err)
            goto error;
    }

    UA_TrustListDataType_clear(&trustList);

    error:
    UA_TrustListDataType_clear(&trustList);
    if(err) {
        retval = UA_STATUSCODE_BADINTERNALERROR;
    }
    return retval;
}

static UA_StatusCode
FileCertStore_verifyCertificate(UA_CertificateGroup *certGroup,
                               const UA_ByteString *certificate,
                               const UA_ByteString *issuerCertificates,
                               size_t issuerCertificatesSize) {
    /* Check parameter */
    if(certGroup == NULL || certificate == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    CertInfo ci;
    CertInfo_init(&ci);
    UA_StatusCode certFlag = reloadCertificates(&ci, certGroup, issuerCertificates, issuerCertificatesSize);
    if(certFlag != UA_STATUSCODE_GOOD) {
        return certFlag;
    }

    /* Accept the certificate if the store is empty */
    /* TODO: Intended? */
    if(ci.trustedCertificates.raw.len == 0 &&
       ci.trustedIssuers.raw.len == 0 &&
       ci.trustedCertificateCrls.raw.len == 0 &&
       ci.trustedIssuerCrls.raw.len == 0) {
        UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_USERLAND,
                       "No certificate store configured. Accepting the certificate.");
        return UA_STATUSCODE_GOOD;
    }

    /* Parse the certificate */
    mbedtls_x509_crt remoteCertificate;

    /* Temporary Object to parse the trustList */
    mbedtls_x509_crt *tempCert = NULL;

    /* Temporary Object to parse the revocationList */
    mbedtls_x509_crl *tempCrl = NULL;

    /* Temporary Object to identify the parent CA when there is no intermediate CA */
    mbedtls_x509_crt *parentCert = NULL;

    /* Temporary Object to identify the parent CA when there is intermediate CA */
    mbedtls_x509_crt *parentCert_2 = NULL;

    /* Flag value to identify if the issuer certificate is found */
    int issuerKnown = 0;

    /* Flag value to identify if the parent certificate found */
    int parentFound = 0;

    mbedtls_x509_crt_init(&remoteCertificate);
    int mbedErr = mbedtls_x509_crt_parse(&remoteCertificate, certificate->data,
                                         certificate->length);
    if(mbedErr) {
        /* char errBuff[300]; */
        /* mbedtls_strerror(mbedErr, errBuff, 300); */
        /* UA_LOG_WARNING(data->policyContext->securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY, */
        /*                "Could not parse the remote certificate with error: %s", errBuff); */
        CertInfo_clear(&ci);
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    /* Verify */
    mbedtls_x509_crt_profile crtProfile = {
            MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1) | MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256),
            0xFFFFFF, 0x000000, 128 * 8 // in bits
    }; // TODO: remove magic numbers

    uint32_t flags = 0;
    mbedErr = mbedtls_x509_crt_verify_with_profile(&remoteCertificate,
                                                   &ci.trustedCertificates,
                                                   &ci.trustedCertificateCrls,
                                                   &crtProfile, NULL, &flags, NULL, NULL);

    /* Flag to check if the remote certificate is trusted or not */
    int TRUSTED = 0;

    /* Check if the remoteCertificate is present in the trustList while mbedErr value is not zero */
    if(mbedErr && !(flags & MBEDTLS_X509_BADCERT_EXPIRED) && !(flags & MBEDTLS_X509_BADCERT_FUTURE)) {
        for(tempCert = &ci.trustedCertificates; tempCert != NULL; tempCert = tempCert->next) {
            if(remoteCertificate.raw.len == tempCert->raw.len &&
               memcmp(remoteCertificate.raw.p, tempCert->raw.p, remoteCertificate.raw.len) == 0) {
                TRUSTED = REMOTECERTIFICATETRUSTED;
                break;
            }
        }
    }

    /* If the remote certificate is present in the trustList then check if the issuer certificate
     * of remoteCertificate is present in issuerList */
    if(TRUSTED && mbedErr) {
        mbedErr = mbedtls_x509_crt_verify_with_profile(&remoteCertificate,
                                                       &ci.trustedIssuers,
                                                       &ci.trustedIssuerCrls,
                                                       &crtProfile, NULL, &flags, NULL, NULL);

        /* Check if the parent certificate has a CRL file available */
        if(!mbedErr) {
            /* Flag value to identify if that there is an intermediate CA present */
            int dualParent = 0;

            /* Identify the topmost parent certificate for the remoteCertificate */
            for(parentCert = &ci.trustedIssuers; parentCert != NULL; parentCert = parentCert->next ) {
                if(memcmp(remoteCertificate.issuer_raw.p, parentCert->subject_raw.p, parentCert->subject_raw.len) == 0) {
                    for(parentCert_2 = &ci.trustedCertificates; parentCert_2 != NULL; parentCert_2 = parentCert_2->next) {
                        if(memcmp(parentCert->issuer_raw.p, parentCert_2->subject_raw.p, parentCert_2->subject_raw.len) == 0) {
                            dualParent = DUALPARENT;
                            break;
                        }
                    }
                    parentFound = PARENTFOUND;
                }

                if(parentFound == PARENTFOUND)
                    break;
            }

            /* Check if there is an intermediate certificate between the topmost parent
             * certificate and child certificate
             * If yes the topmost parent certificate is to be checked whether it has a
             * CRL file avaiable */
            if(dualParent == DUALPARENT && parentFound == PARENTFOUND) {
                parentCert = parentCert_2;
            }

            /* If a parent certificate is found traverse the revocationList and identify
             * if there is any CRL file that corresponds to the parentCertificate */
            if(parentFound == PARENTFOUND) {
                tempCrl = &ci.trustedCertificateCrls;
                while(tempCrl != NULL) {
                    if(tempCrl->version != 0 &&
                       tempCrl->issuer_raw.len == parentCert->subject_raw.len &&
                       memcmp(tempCrl->issuer_raw.p,
                              parentCert->subject_raw.p,
                              tempCrl->issuer_raw.len) == 0) {
                        issuerKnown = ISSUERKNOWN;
                        break;
                    }

                    tempCrl = tempCrl->next;
                }

                /* If the CRL file corresponding to the parent certificate is not present
                 * then return UA_STATUSCODE_BADCERTIFICATEISSUERREVOCATIONUNKNOWN */
                if(!issuerKnown) {
                    if(FileCertStore_addToRejectedList(certGroup, certificate) != UA_STATUSCODE_GOOD) {
                        UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                       "Could not append certificate to rejected list");
                    }
                    CertInfo_clear(&ci);
                    return UA_STATUSCODE_BADCERTIFICATEISSUERREVOCATIONUNKNOWN;
                }
            }
        }
    }
    else if(!mbedErr && !TRUSTED) {
        /* This else if section is to identify if the parent certificate which is present in trustList
         * has CRL file corresponding to it */

        /* Identify the parent certificate of the remoteCertificate */
        for(parentCert = &ci.trustedCertificates; parentCert != NULL; parentCert = parentCert->next) {
            if(memcmp(remoteCertificate.issuer_raw.p, parentCert->subject_raw.p, parentCert->subject_raw.len) == 0) {
                parentFound = PARENTFOUND;
                break;
            }
        }

        /* If the parent certificate is found traverse the revocationList and identify
         * if there is any CRL file that corresponds to the parentCertificate */
        if(parentFound == PARENTFOUND &&
           memcmp(remoteCertificate.issuer_raw.p, remoteCertificate.subject_raw.p, remoteCertificate.subject_raw.len) != 0) {
            tempCrl = &ci.trustedCertificateCrls;
            while(tempCrl != NULL) {
                if(tempCrl->version != 0 &&
                   tempCrl->issuer_raw.len == parentCert->subject_raw.len &&
                   memcmp(tempCrl->issuer_raw.p,
                          parentCert->subject_raw.p,
                          tempCrl->issuer_raw.len) == 0) {
                    issuerKnown = ISSUERKNOWN;
                    break;
                }

                tempCrl = tempCrl->next;
            }

            /* If the CRL file corresponding to the parent certificate is not present
             * then return UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN */
            if(!issuerKnown) {
                if(FileCertStore_addToRejectedList(certGroup, certificate) != UA_STATUSCODE_GOOD) {
                    UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                   "Could not append certificate to rejected list");
                }
                CertInfo_clear(&ci);
                return UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN;
            }

        }

    }

    // TODO: Extend verification

    /* This condition will check whether the certificate is a User certificate
     * or a CA certificate. If the MBEDTLS_X509_KU_KEY_CERT_SIGN and
     * MBEDTLS_X509_KU_CRL_SIGN of key_usage are set, then the certificate
     * shall be condidered as CA Certificate and cannot be used to establish a
     * connection. Refer the test case CTT/Security/Security Certificate Validation/029.js
     * for more details */
#if MBEDTLS_VERSION_NUMBER >= 0x02060000 && MBEDTLS_VERSION_NUMBER < 0x03000000
    if((remoteCertificate.key_usage & MBEDTLS_X509_KU_KEY_CERT_SIGN) &&
       (remoteCertificate.key_usage & MBEDTLS_X509_KU_CRL_SIGN)) {
        if(FileCertStore_addToRejectedList(certGroup, certificate) != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                           "Could not append certificate to rejected list");
        }
        CertInfo_clear(&ci);
        return UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED;
    }
#else
    if((remoteCertificate.private_key_usage & MBEDTLS_X509_KU_KEY_CERT_SIGN) &&
       (remoteCertificate.private_key_usage & MBEDTLS_X509_KU_CRL_SIGN)) {
        if(certGroup->addToRejectedList(certGroup, certificate) != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                           "Could not append certificate to rejected list");
        }
        CertInfo_clear(&ci);
        return UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED;
    }
#endif


    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(mbedErr) {
#if UA_LOGLEVEL <= 400
        char buff[100];
        int len = mbedtls_x509_crt_verify_info(buff, 100, "", flags);
        UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                       "Verifying the certificate failed with error: %.*s", len-1, buff);
#endif
        if(flags & (uint32_t)MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
            if(FileCertStore_addToRejectedList(certGroup, certificate) != UA_STATUSCODE_GOOD) {
                UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                               "Could not append certificate to rejected list");
            }
            retval = UA_STATUSCODE_BADCERTIFICATEUNTRUSTED;
        } else if(flags & (uint32_t)MBEDTLS_X509_BADCERT_FUTURE ||
                  flags & (uint32_t)MBEDTLS_X509_BADCERT_EXPIRED) {
            retval = UA_STATUSCODE_BADCERTIFICATETIMEINVALID;
            /* Debug purpose */
        } else if(flags & (uint32_t)MBEDTLS_X509_BADCERT_REVOKED ||
                  flags & (uint32_t)MBEDTLS_X509_BADCRL_EXPIRED) {
            retval = UA_STATUSCODE_BADCERTIFICATEREVOKED;
        } else {
            retval = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
        }
    }

    CertInfo_clear(&ci);
    mbedtls_x509_crt_free(&remoteCertificate);
    return retval;
}

UA_StatusCode
UA_CertificateGroup_Filestore(UA_CertificateGroup *certGroup, UA_NodeId *certificateGroupId, UA_String *storePath) {
    /* Check parameter */
    if(certGroup == NULL || certificateGroupId == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if(certGroup->clear)
        certGroup->clear(certGroup);

    UA_NodeId_copy(certificateGroupId, &certGroup->certificateGroupId);

    /* Create root directory */
    char* rootDir = NULL;
    size_t rootDirLen = 0;
    UA_StatusCode retval = FileCertStore_createRootDirectory(storePath, certificateGroupId, &rootDir, &rootDirLen);
    if (retval != UA_STATUSCODE_GOOD || rootDir == NULL) {
        if (rootDir) UA_free(rootDir);
        return retval;
    }

    /* Set PKi Store data */
    certGroup->getTrustList = FileCertStore_getTrustList;
    certGroup->setTrustList = FileCertStore_setTrustList;

    certGroup->addToTrustList = FileCertStore_addToTrustList;
    certGroup->removeFromTrustList = FileCertStore_removeFromTrustList;

    certGroup->getRejectedList = FileCertStore_getRejectedList;

    certGroup->verifyCertificate = FileCertStore_verifyCertificate;

    certGroup->clear = FileCertStore_clear;

    /* Set PKI Store context data */
    FileCertStore *context = (FileCertStore *)UA_malloc(sizeof(FileCertStore));
    context->rootDir = rootDir;
    context->rootDirLen = rootDirLen;
    certGroup->context = context;

    retval |= FileCertStore_setupStorePath("/trusted/certs", rootDir, rootDirLen, &context->trustedCertDir);
    retval |= FileCertStore_setupStorePath("/trusted/crl", rootDir, rootDirLen, &context->trustedCrlDir);
    retval |= FileCertStore_setupStorePath("/issuer/certs", rootDir, rootDirLen, &context->trustedIssuerCertDir);
    retval |= FileCertStore_setupStorePath("/issuer/crl", rootDir, rootDirLen, &context->trustedIssuerCrlDir);
    retval |= FileCertStore_setupStorePath("/rejected/certs", rootDir, rootDirLen, &context->rejectedCertDir);

    if(retval != UA_STATUSCODE_GOOD) {
        certGroup->clear(certGroup);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_CertificateUtils_verifyApplicationURI(UA_RuleHandling ruleHandling,
                                         const UA_ByteString *certificate,
                                         const UA_String *applicationURI) {
    /* Parse the certificate */
    mbedtls_x509_crt remoteCertificate;
    mbedtls_x509_crt_init(&remoteCertificate);
    int mbedErr = mbedtls_x509_crt_parse(&remoteCertificate, certificate->data,
                                         certificate->length);
    if(mbedErr)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    /* Poor man's ApplicationUri verification. mbedTLS does not parse all fields
     * of the Alternative Subject Name. Instead test whether the URI-string is
     * present in the v3_ext field in general.
     *
     * TODO: Improve parsing of the Alternative Subject Name */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(UA_Bstrstr(remoteCertificate.v3_ext.p, remoteCertificate.v3_ext.len,
                  applicationURI->data, applicationURI->length) == NULL)
        retval = UA_STATUSCODE_BADCERTIFICATEURIINVALID;

    if(retval != UA_STATUSCODE_GOOD && ruleHandling == UA_RULEHANDLING_DEFAULT) {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                       "The certificate's application URI could not be verified. StatusCode %s",
                       UA_StatusCode_name(retval));
        retval = UA_STATUSCODE_GOOD;
    }
    mbedtls_x509_crt_free(&remoteCertificate);
    return retval;
}

UA_StatusCode
UA_CertificateUtils_getExpirationDate(UA_ByteString *certificate,
                                      UA_DateTime *expiryDateTime) {
    mbedtls_x509_crt publicKey;
    mbedtls_x509_crt_init(&publicKey);
    int mbedErr = mbedtls_x509_crt_parse(&publicKey, certificate->data, certificate->length);
    if(mbedErr)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_DateTimeStruct ts;
    ts.year = (UA_Int16)publicKey.valid_to.year;
    ts.month = (UA_UInt16)publicKey.valid_to.mon;
    ts.day = (UA_UInt16)publicKey.valid_to.day;
    ts.hour = (UA_UInt16)publicKey.valid_to.hour;
    ts.min = (UA_UInt16)publicKey.valid_to.min;
    ts.sec = (UA_UInt16)publicKey.valid_to.sec;
    ts.milliSec = 0;
    ts.microSec = 0;
    ts.nanoSec = 0;
    *expiryDateTime = UA_DateTime_fromStruct(ts);
    mbedtls_x509_crt_free(&publicKey);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_CertificateUtils_getSubjectName(UA_ByteString *certificate,
                                   UA_String *subjectName) {
    mbedtls_x509_crt publicKey;
    mbedtls_x509_crt_init(&publicKey);
    int mbedErr = mbedtls_x509_crt_parse(&publicKey, certificate->data, certificate->length);
    if(mbedErr)
        return UA_STATUSCODE_BADINTERNALERROR;
    char buf[1024];
    int res = mbedtls_x509_dn_gets(buf, 1024, &publicKey.subject);
    mbedtls_x509_crt_free(&publicKey);
    if(res < 0)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_String tmp = {(size_t)res, (UA_Byte*)buf};
    return UA_String_copy(&tmp, subjectName);
}

UA_StatusCode
UA_CertificateUtils_getThumbprint(UA_ByteString *certificate,
                                  UA_String *thumbprint){
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(certificate == NULL || thumbprint->length != (UA_SHA1_LENGTH * 2))
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_ByteString thumbpr = UA_BYTESTRING_NULL;
    UA_ByteString_allocBuffer(&thumbpr, UA_SHA1_LENGTH);

    retval = mbedtls_thumbprint_sha1(certificate, &thumbpr);

    UA_String thumb = UA_STRING_NULL;
    thumb.length = (UA_SHA1_LENGTH * 2) + 1;
    thumb.data = (UA_Byte*)malloc(sizeof(UA_Byte)*thumb.length);

    // Create a string containing a hex representation
    char *p = (char*)thumb.data;
    for (size_t i = 0; i < thumbpr.length; i++) {
        p += sprintf(p, "%.2X", thumbpr.data[i]);
    }

    memcpy(thumbprint->data, thumb.data, thumbprint->length);

    UA_ByteString_clear(&thumbpr);
    UA_ByteString_clear(&thumb);

    return retval;
}

UA_StatusCode
UA_CertificateUtils_decryptPrivateKey(const UA_ByteString privateKey,
                                      const UA_ByteString password,
                                      UA_ByteString *outDerKey) {
    if(!outDerKey)
        return UA_STATUSCODE_BADINTERNALERROR;

    if (privateKey.length == 0) {
        *outDerKey = UA_BYTESTRING_NULL;
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    /* Already in DER format -> return verbatim */
    if(privateKey.length > 1 && privateKey.data[0] == 0x30 && privateKey.data[1] == 0x82)
        return UA_ByteString_copy(&privateKey, outDerKey);

    /* Create a null-terminated string */
    UA_ByteString nullTerminatedKey = UA_mbedTLS_CopyDataFormatAware(&privateKey);
    if(nullTerminatedKey.length != privateKey.length + 1)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    /* Create the private-key context */
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
#if MBEDTLS_VERSION_NUMBER >= 0x02060000 && MBEDTLS_VERSION_NUMBER < 0x03000000
    int err = mbedtls_pk_parse_key(&ctx, nullTerminatedKey.data,
                                   nullTerminatedKey.length,
                                   password.data, password.length);
#else
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    int err = mbedtls_pk_parse_key(&ctx, nullTerminatedKey.data,
                                   nullTerminatedKey.length,
                                   password.data, password.length,
                                   mbedtls_entropy_func, &entropy);
    mbedtls_entropy_free(&entropy);
#endif
    UA_ByteString_clear(&nullTerminatedKey);
    if(err != 0) {
        mbedtls_pk_free(&ctx);
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    /* Write the DER-encoded key into a local buffer */
    unsigned char buf[2 << 13];
    size_t pos = (size_t)mbedtls_pk_write_key_der(&ctx, buf, sizeof(buf));

    /* Allocate memory */
    UA_StatusCode res = UA_ByteString_allocBuffer(outDerKey, pos);
    if(res != UA_STATUSCODE_GOOD) {
        mbedtls_pk_free(&ctx);
        return res;
    }

    /* Copy to the output */
    memcpy(outDerKey->data, &buf[sizeof(buf) - pos], pos);
    mbedtls_pk_free(&ctx);
    return UA_STATUSCODE_GOOD;
}

#endif
