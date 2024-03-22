/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2022 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2023 (c) Fraunhofer IOSB (Author: Kai Huebl)
 *    Copyright 2024 (c) Fraunhofer IOSB (Author: Noel Graf)
 */

#include <open62541/util.h>

#include "ua_certificategroup_common.h"

#include <dirent.h>
#include <sys/stat.h>
#include <libgen.h>
#include <stdio.h>
#include <unistd.h>


UA_StatusCode
readFileToByteString(const char *const path, UA_ByteString *data) {
    if (path == NULL || data == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Open the file */
    FILE *fp = fopen(path, "rb");
    if(!fp) {
        return UA_STATUSCODE_BADNOTFOUND;
    }

    /* Get the file length, allocate the data and read */
    fseek(fp, 0, SEEK_END);
    UA_StatusCode retval = UA_ByteString_allocBuffer(data, (size_t)ftell(fp));
    if(retval == UA_STATUSCODE_GOOD) {
        fseek(fp, 0, SEEK_SET);
        size_t read = fread(data->data, sizeof(UA_Byte), data->length * sizeof(UA_Byte), fp);
        if(read != data->length) {
            UA_ByteString_clear(data);
        }
    } else {
        data->length = 0;
    }
    fclose(fp);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
writeByteStringToFile(const char *const path, const UA_ByteString *data) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* Open the file */
    FILE *fp = fopen(path, "wb");
    if(!fp) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Write byte string to file */
    size_t len = fwrite(data->data, sizeof(UA_Byte), data->length * sizeof(UA_Byte), fp);
    if(len != data->length) {
        fclose(fp);
        retval = UA_STATUSCODE_BADINTERNALERROR;
    }

    fclose(fp);
    return retval;
}

static UA_StatusCode
deleteFileFromFilestore(char *path, const UA_ByteString oldCertificate, const UA_ByteString newCertificate,
                        char **matchedFilename, bool *fileDeleted) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    *fileDeleted = false;

    /* Check if the file is stored in CertStore and delete it */
    /* Determine number of files and if the new certificate is already stored */
    size_t numCerts = 0;
    DIR *dir = opendir(path);
    if(dir) {
        struct dirent *dirent;
        while((dirent = readdir(dir)) != NULL) {
            if(dirent->d_type == DT_REG) {
                /* Create filename to load */
                char filename[FILENAME_MAX];
                if(snprintf(filename, FILENAME_MAX, "%s/%s", path, dirent->d_name) < 0) {
                    closedir(dir);
                    return UA_STATUSCODE_BADINTERNALERROR;
                }

                /* Load data from file */
                UA_ByteString fileData;
                retval = readFileToByteString(filename, &fileData);
                if (retval != UA_STATUSCODE_GOOD) {
                    closedir(dir);
                    UA_ByteString_clear(&fileData);
                    return retval;
                }

                if (UA_ByteString_equal(&newCertificate, &fileData)) {
                    /* new certificate is already stored */
                    closedir(dir);
                    UA_ByteString_clear(&fileData);
                    return UA_STATUSCODE_GOOD;
                }
                UA_ByteString_clear(&fileData);
                numCerts++;
            }
        }
        closedir(dir);
    }

    /* Read files from directory */
    dir = opendir(path);
    if (dir) {
        struct dirent *dirent;
        while ((dirent = readdir(dir)) != NULL) {
            if (dirent->d_type == DT_REG) {

                /* Create filename to load */
                char filename[FILENAME_MAX];
                if(snprintf(filename, FILENAME_MAX, "%s/%s", path, dirent->d_name) < 0) {
                    closedir(dir);
                    return UA_STATUSCODE_BADINTERNALERROR;
                }

                /* Load data from file */
                UA_ByteString fileData;
                retval = readFileToByteString(filename, &fileData);
                if (retval != UA_STATUSCODE_GOOD) {
                    closedir(dir);
                    UA_ByteString_clear(&fileData);
                    return retval;
                }
                if (UA_ByteString_equal(&oldCertificate, &fileData)) {
                    size_t keySize = 0;
                    UA_CertificateUtils_getKeySize((UA_ByteString*)(uintptr_t)&oldCertificate, &keySize);
                    if(numCerts > 1 || (numCerts == 1 && (keySize > 256 || keySize == 128))) {
                        if (remove(filename) != 0) {
                            closedir(dir);
                            UA_ByteString_clear(&fileData);
                            return UA_STATUSCODE_BADINTERNALERROR;
                        }
                        *fileDeleted = true;
                    }
                    *matchedFilename = strndup(dirent->d_name, strlen(dirent->d_name) - 4);
                }
                UA_ByteString_clear(&fileData);
            }
        }
        closedir(dir);
    }
    return retval;
}

UA_StatusCode
writeCertificateAndPrivateKeyToFilestore(const UA_String storePath, const UA_ByteString oldCertificate,
                                         const UA_ByteString newCertificate, const UA_ByteString newPrivateKey) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* Certificate handling */
    char *ownCertPath = "/own/certs";
    size_t ownCertPathLen = strlen(ownCertPath);

    char *certFilePath = (char*)UA_malloc(storePath.length + ownCertPathLen + 1);
    memcpy(certFilePath, storePath.data, storePath.length);
    memcpy(certFilePath + storePath.length, ownCertPath, ownCertPathLen);
    certFilePath[storePath.length + ownCertPathLen] = '\0';

    char certFilename[FILENAME_MAX];
    retval = getCertFileName(certFilePath, &newCertificate, certFilename, FILENAME_MAX - 5);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_free(certFilePath);
        return retval;
    }
    strncat(certFilename, ".der", 5);

    char *matchedFilename  = NULL;
    bool fileDeleted = false;
    retval = deleteFileFromFilestore(certFilePath, oldCertificate, newCertificate, &matchedFilename, &fileDeleted);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_free(certFilePath);
        return retval;
    }
    UA_free(certFilePath);

    /* The old certificate could not be found in the file system.
     * Already updated. */
    if(!matchedFilename) {
        return UA_STATUSCODE_GOOD;
    }

    retval = writeByteStringToFile(certFilename, &newCertificate);
    if (retval != UA_STATUSCODE_GOOD) {
        return retval;
    }

    /* Private key handling */
    char *ownKeyPath = "/own/private";
    size_t ownKeyPathLen = strlen(ownKeyPath);

    char *keyFilePath = (char*)UA_malloc(storePath.length + ownKeyPathLen + 1);
    memcpy(keyFilePath, storePath.data, storePath.length);
    memcpy(keyFilePath + storePath.length, ownKeyPath, ownKeyPathLen);
    keyFilePath[storePath.length + ownKeyPathLen] = '\0';

    char keyFilename[FILENAME_MAX];
    retval = getCertFileName(keyFilePath, &newCertificate, keyFilename, FILENAME_MAX - 5);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_free(keyFilePath);
        return retval;
    }
    strncat(keyFilename, ".key", 5);

    char *tmp = NULL;
    if(newPrivateKey.length == 0 || fileDeleted) {
        size_t tmpLen = strlen(keyFilePath) + strlen(matchedFilename) + 6;
        tmp = (char *)UA_malloc(tmpLen);
        if(!tmp) {
            UA_free(matchedFilename);
            UA_free(keyFilePath);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        memset(tmp, 0, tmpLen);
        strncpy(tmp, keyFilePath, strlen(keyFilePath));
        strncat(tmp, "/", 2);
        strncat(tmp, matchedFilename, strlen(matchedFilename));
        strncat(tmp, ".key", 5);
    }

    UA_ByteString newKeyData;
    if(newPrivateKey.length > 0) {
        newKeyData = newPrivateKey;
    } else {
        retval = readFileToByteString(tmp, &newKeyData);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_free(tmp);
            return retval;
        }
    }
    retval = writeByteStringToFile(keyFilename, &newKeyData);
    if(retval != UA_STATUSCODE_GOOD) {
        if(tmp)
            UA_free(tmp);
        else {
            UA_free(matchedFilename);
        }
        return retval;
    }
    if(fileDeleted) {
        if(remove(tmp) != 0) {
            UA_free(tmp);
            return UA_STATUSCODE_BADINTERNALERROR;
        }
    }

    if(tmp) {
        UA_free(tmp);
        UA_free(matchedFilename);
    } else {
        UA_free(matchedFilename);
    }
    UA_free(keyFilePath);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
removeAllFilesFromDir(const char *const path, bool removeSubDirs) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* Check parameter */
    if (path == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* remove all regular files from directory */
    DIR *dir = opendir(path);
    if(dir) {
        struct dirent *dirent;
        while((dirent = readdir(dir)) != NULL) {
            if(dirent->d_type == DT_REG) {
                char file_name[FILENAME_MAX];
                snprintf(file_name, FILENAME_MAX, "%s/%s", path, (char*)dirent->d_name);
                remove(file_name);
            }
            else if (dirent->d_type == DT_DIR && removeSubDirs == true) {
                char* directory = (char*)dirent->d_name;

                char dir_name[FILENAME_MAX];
                snprintf(dir_name, FILENAME_MAX, "%s/%s", path, (char*)dirent->d_name);

                if (strlen(directory) == 1 && directory[0] == '.') continue;
                if (strlen(directory) == 2 && directory[0] == '.' && directory[1] == '.') continue;

                removeAllFilesFromDir(dir_name, removeSubDirs);
                /*rmdir(dir_name);*/
            }
        }
        closedir(dir);
    }
    return retval;
}

static char* copyStr(const char* s) {
    size_t len = 1+strlen(s);
    char* p = (char*)malloc(len);
    p[len-1] = 0x00;
    return p ? (char*)memcpy(p, s, len) : NULL;
}

static int
mkpath(char *dir, mode_t mode) {
    struct stat sb;

    if(dir == NULL) {
        return 1;
    }

    if(!stat(dir, &sb)) {
        /* Directory already exist */
        return 0;
    }

    char* tmp_dir = copyStr(dir);
    mkpath(dirname(tmp_dir), mode);
    free(tmp_dir);

    return mkdir(dir, mode);
}

UA_StatusCode
getCertFileName(const char* path, const UA_ByteString *certificate,
                char *fileNameBuf, size_t fileNameLen) {
    /* Check parameter */
    if (path == NULL || certificate == NULL || fileNameBuf == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    UA_String thumbprint = UA_STRING_NULL;
    thumbprint.length = 40;
    thumbprint.data = (UA_Byte*)malloc(sizeof(UA_Byte)*thumbprint.length);

    UA_String subjectName = UA_STRING_NULL;

    UA_CertificateUtils_getThumbprint((UA_ByteString*)(uintptr_t)certificate, &thumbprint);
    UA_CertificateUtils_getSubjectName((UA_ByteString*)(uintptr_t)certificate, &subjectName);

    if((thumbprint.length + subjectName.length + 2) > fileNameLen) {
        UA_String_clear(&thumbprint);
        UA_String_clear(&subjectName);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    char *thumbprintBuffer = (char*)UA_malloc(thumbprint.length + 1);
    char *subjectNameBuffer = (char*)UA_malloc(subjectName.length + 1);

    memcpy(thumbprintBuffer, thumbprint.data, thumbprint.length);
    thumbprintBuffer[thumbprint.length] = '\0';
    memcpy(subjectNameBuffer, subjectName.data, subjectName.length);
    subjectNameBuffer[subjectName.length] = '\0';

    char *subName = NULL;
    char *substring = "CN=";
    char *ptr = strstr(subjectNameBuffer, substring);

    if(ptr != NULL) {
        subName = ptr + 3;
    } else {
        subName = subjectNameBuffer;
    }

    if(snprintf(fileNameBuf, fileNameLen, "%s/%s[%s]", path, subName, thumbprintBuffer) < 0) {
        retval = UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_String_clear(&thumbprint);
    UA_String_clear(&subjectName);
    UA_free(thumbprintBuffer);
    UA_free(subjectNameBuffer);

    return retval;
}

static UA_StatusCode
loadList(UA_ByteString **list, size_t *listSize, const char *listPath) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* Determine number of certificates */
    size_t numCerts = 0;
    DIR *dir = opendir(listPath);
    if(dir) {
        struct dirent *dirent;
        while((dirent = readdir(dir)) != NULL) {
            if(dirent->d_type == DT_REG) {
                numCerts++;
            }
        }
        closedir(dir);
    }

    retval = UA_Array_resize((void **)list, listSize, numCerts, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if (retval != UA_STATUSCODE_GOOD) {
        return retval;
    }

    /* Read files from directory */
    size_t numActCerts = 0;
    dir = opendir(listPath);
    if(dir) {
        struct dirent *dirent;
        while((dirent = readdir(dir)) != NULL) {
            if(dirent->d_type == DT_REG) {

                if (numActCerts < numCerts) {
                    /* Create filename to load */
                    char filename[FILENAME_MAX];
                    if(snprintf(filename, FILENAME_MAX, "%s/%s", listPath, dirent->d_name) < 0) {
                        closedir(dir);
                        return UA_STATUSCODE_BADINTERNALERROR;
                    }

                    /* Load data from file */
                    retval = readFileToByteString(filename, &((*list)[numActCerts]));
                    if (retval != UA_STATUSCODE_GOOD) {
                        closedir(dir);
                        return retval;
                    }
                }

                numActCerts++;
            }
        }
        closedir(dir);
    }

    return retval;
}

static bool
checkCertificateInList(UA_CertificateGroup *certGroup, const UA_ByteString *certificate) {
    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    UA_StatusCode retval = certGroup->getTrustList(certGroup, &trustList);

    bool inListContained = false;

    if(retval != UA_STATUSCODE_GOOD) {
        UA_TrustListDataType_clear(&trustList);
        return retval;
    }

    for(size_t i = 0; i < trustList.trustedCertificatesSize; i++) {
        if(UA_ByteString_equal(certificate, &trustList.trustedCertificates[i]))
            inListContained = true;
    }
    for(size_t i = 0; i < trustList.issuerCertificatesSize; i++) {
        if(UA_ByteString_equal(certificate, &trustList.issuerCertificates[i]))
            inListContained = true;
    }

    UA_TrustListDataType_clear(&trustList);

    return inListContained;
}

static UA_StatusCode
storeList(UA_CertificateGroup *certGroup, const UA_ByteString *list,
          size_t listSize, const char *listPath) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* Check parameter */
    if (listPath == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    if (listSize > 0 && list == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Store new byte strings */
    for (size_t idx = 0; idx < listSize; idx++) {
        /* Check if certificate is already in list */
        if(checkCertificateInList(certGroup, &list[idx]))
            continue;
        /* Create filename to load */
        char filename[FILENAME_MAX];
        retval = getCertFileName(listPath, &list[idx], filename, FILENAME_MAX);
        if(retval != UA_STATUSCODE_GOOD) {
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        /* Store data in file */
        retval = writeByteStringToFile(filename, &list[idx]);
        if (retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }

    return retval;
}

static UA_StatusCode
newList(UA_CertificateGroup *certGroup, const UA_ByteString *list,
        size_t listSize, const char *listPath) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* Check parameter */
    if (listPath == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    if (listSize > 0 && list == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* remove existing files in directory */
    retval = removeAllFilesFromDir(listPath, false);
    if (retval != UA_STATUSCODE_GOOD) {
        return retval;
    }

    /* Store new byte strings */
    retval = storeList(certGroup, list, listSize, listPath);

    return retval;
}

UA_StatusCode
FileCertStore_removeFromTrustList(UA_CertificateGroup *certGroup, const UA_TrustListDataType *trustList) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    UA_TrustListDataType groupTrustList;
    memset(&groupTrustList, 0, sizeof(UA_TrustListDataType));
    groupTrustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;

    certGroup->getTrustList(certGroup, &groupTrustList);

    /* remove trusted certificates */
    if(groupTrustList.trustedCertificatesSize > 0 && trustList->trustedCertificatesSize > 0) {
        UA_ByteString *list = (UA_ByteString*)UA_malloc(sizeof(UA_ByteString) * groupTrustList.trustedCertificatesSize);
        memset(list, 0, sizeof(UA_ByteString)*groupTrustList.trustedCertificatesSize);
        size_t size = groupTrustList.trustedCertificatesSize;
        size_t listSize = 0;
        bool isContained = false;
        for(size_t i = 0; i < groupTrustList.trustedCertificatesSize; i++) {
            for(size_t j = 0; j < trustList->trustedCertificatesSize; j++) {
                if(UA_ByteString_equal(&groupTrustList.trustedCertificates[i], &trustList->trustedCertificates[j]))
                    isContained = true;
            }
            if(!isContained)
                UA_ByteString_copy(&groupTrustList.trustedCertificates[i], &list[listSize++]);
            isContained = false;
        }
        if(listSize < groupTrustList.trustedCertificatesSize) {
            if(listSize == 0) {
                UA_Array_delete(list, size, &UA_TYPES[UA_TYPES_BYTESTRING]);
                list = NULL;
            } else {
                retval = UA_Array_resize((void**)&list, &size, listSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
                if (retval != UA_STATUSCODE_GOOD) {
                    UA_free(list);
                    return retval;
                }
            }
        }
        UA_Array_delete(groupTrustList.trustedCertificates, groupTrustList.trustedCertificatesSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
        groupTrustList.trustedCertificatesSize = 0;
        groupTrustList.trustedCertificates = list;
        groupTrustList.trustedCertificatesSize = listSize;
    }

    /* remove issuer certificates */
    if(groupTrustList.issuerCertificatesSize > 0 && trustList->issuerCertificatesSize > 0) {
        UA_ByteString *list = (UA_ByteString*)UA_malloc(sizeof(UA_ByteString) * groupTrustList.issuerCertificatesSize);
        memset(list, 0, sizeof(UA_ByteString)*groupTrustList.issuerCertificatesSize);
        size_t size = groupTrustList.issuerCertificatesSize;
        size_t listSize = 0;
        bool isContained = false;
        for(size_t i = 0; i < groupTrustList.issuerCertificatesSize; i++) {
            for(size_t j = 0; j < trustList->issuerCertificatesSize; j++) {
                if(UA_ByteString_equal(&groupTrustList.issuerCertificates[i], &trustList->issuerCertificates[j]))
                    isContained = true;
            }
            if(!isContained)
                UA_ByteString_copy(&groupTrustList.issuerCertificates[i], &list[listSize++]);
            isContained = false;
        }
        if(listSize < groupTrustList.issuerCertificatesSize) {
            if(listSize == 0) {
                UA_Array_delete(list, size, &UA_TYPES[UA_TYPES_BYTESTRING]);
                list = NULL;
            } else {
                retval = UA_Array_resize((void**)&list, &size, listSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
                if (retval != UA_STATUSCODE_GOOD) {
                    UA_free(list);
                    return retval;
                }
            }
        }
        UA_Array_delete(groupTrustList.issuerCertificates, groupTrustList.issuerCertificatesSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
        groupTrustList.issuerCertificatesSize = 0;
        groupTrustList.issuerCertificates = list;
        groupTrustList.issuerCertificatesSize = listSize;
    }

    /* remove trusted crls */
    if(groupTrustList.trustedCrlsSize > 0 && trustList->trustedCrlsSize > 0) {
        UA_ByteString *list = (UA_ByteString*)UA_malloc(sizeof(UA_ByteString) * groupTrustList.trustedCrlsSize);
        memset(list, 0, sizeof(UA_ByteString)*groupTrustList.trustedCrlsSize);
        size_t size = groupTrustList.trustedCrlsSize;
        size_t listSize = 0;
        bool isContained = false;
        for(size_t i = 0; i < groupTrustList.trustedCrlsSize; i++) {
            for(size_t j = 0; j < trustList->trustedCrlsSize; j++) {
                if(UA_ByteString_equal(&groupTrustList.trustedCrls[i], &trustList->trustedCrls[j]))
                    isContained = true;
            }
            if(!isContained)
                UA_ByteString_copy(&groupTrustList.trustedCrls[i], &list[listSize++]);
            isContained = false;
        }
        if(listSize < groupTrustList.trustedCrlsSize) {
            if(listSize == 0) {
                UA_Array_delete(list, size, &UA_TYPES[UA_TYPES_BYTESTRING]);
                list = NULL;
            } else {
                retval = UA_Array_resize((void**)&list, &size, listSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
                if (retval != UA_STATUSCODE_GOOD) {
                    UA_free(list);
                    return retval;
                }
            }
        }
        UA_Array_delete(groupTrustList.trustedCrls, groupTrustList.trustedCrlsSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
        groupTrustList.trustedCrlsSize = 0;
        groupTrustList.trustedCrls = list;
        groupTrustList.trustedCrlsSize = listSize;
    }

    /* remove issuer crls */
    if(groupTrustList.issuerCrlsSize > 0 && trustList->issuerCrlsSize > 0) {
        UA_ByteString *list = (UA_ByteString*)UA_malloc(sizeof(UA_ByteString) * groupTrustList.issuerCrlsSize);
        memset(list, 0, sizeof(UA_ByteString)*groupTrustList.issuerCrlsSize);
        size_t size = groupTrustList.issuerCrlsSize;
        size_t listSize = 0;
        bool isContained = false;
        for(size_t i = 0; i < groupTrustList.issuerCrlsSize; i++) {
            for(size_t j = 0; j < trustList->issuerCrlsSize; j++) {
                if(UA_ByteString_equal(&groupTrustList.issuerCrls[i], &trustList->issuerCrls[j]))
                    isContained = true;
            }
            if(!isContained)
                UA_ByteString_copy(&groupTrustList.issuerCrls[i], &list[listSize++]);
            isContained = false;
        }
        if(listSize < groupTrustList.issuerCrlsSize) {
            if(listSize == 0) {
                UA_Array_delete(list, size, &UA_TYPES[UA_TYPES_BYTESTRING]);
                list = NULL;
            } else {
                retval = UA_Array_resize((void**)&list, &size, listSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
                if (retval != UA_STATUSCODE_GOOD) {
                    UA_free(list);
                    return retval;
                }
            }
        }
        UA_Array_delete(groupTrustList.issuerCrls, groupTrustList.issuerCrlsSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
        groupTrustList.issuerCrlsSize = 0;
        groupTrustList.issuerCrls = list;
        groupTrustList.issuerCrlsSize = listSize;
    }

    certGroup->setTrustList(certGroup, &groupTrustList);

    return retval;
}

UA_StatusCode
FileCertStore_getTrustList(UA_CertificateGroup *certGroup, UA_TrustListDataType *trustList) {
    /* Check parameter */
    if (certGroup == NULL || trustList == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    FileCertStore *context = (FileCertStore *)certGroup->context;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES) {
        retval = loadList(&trustList->trustedCertificates, &trustList->trustedCertificatesSize,
                          context->trustedCertDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_TRUSTEDCRLS) {
        retval = loadList(&trustList->trustedCrls, &trustList->trustedCrlsSize,
                          context->trustedCrlDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_ISSUERCERTIFICATES) {
        retval = loadList(&trustList->issuerCertificates, &trustList->issuerCertificatesSize,
                          context->trustedIssuerCertDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_ISSUERCRLS) {
        retval = loadList(&trustList->issuerCrls, &trustList->issuerCrlsSize,
                          context->trustedIssuerCrlDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    return retval;
}


UA_StatusCode
FileCertStore_setTrustList(UA_CertificateGroup *certGroup, const UA_TrustListDataType *trustList) {
    /* Check parameter */
    if (certGroup == NULL || trustList == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    FileCertStore *context = (FileCertStore *)certGroup->context;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES) {
        retval = newList(certGroup, trustList->trustedCertificates, trustList->trustedCertificatesSize,
                         context->trustedCertDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_TRUSTEDCRLS) {
        retval = newList(certGroup, trustList->trustedCrls, trustList->trustedCrlsSize,
                         context->trustedCrlDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_ISSUERCERTIFICATES) {
        retval = newList(certGroup, trustList->issuerCertificates, trustList->issuerCertificatesSize,
                         context->trustedIssuerCertDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_ISSUERCRLS) {
        retval = newList(certGroup, trustList->issuerCrls, trustList->issuerCrlsSize,
                         context->trustedIssuerCrlDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    return retval;
}

UA_StatusCode
FileCertStore_addToTrustList(UA_CertificateGroup *certGroup, const UA_TrustListDataType *trustList) {
    /* Check parameter */
    if (certGroup == NULL || trustList == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    FileCertStore *context = (FileCertStore *)certGroup->context;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES) {
        retval = storeList(certGroup, trustList->trustedCertificates, trustList->trustedCertificatesSize,
                           context->trustedCertDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_TRUSTEDCRLS) {
        retval = storeList(certGroup, trustList->trustedCrls, trustList->trustedCrlsSize,
                           context->trustedCrlDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_ISSUERCERTIFICATES) {
        retval = storeList(certGroup, trustList->issuerCertificates, trustList->issuerCertificatesSize,
                           context->trustedIssuerCertDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_ISSUERCRLS) {
        retval = storeList(certGroup, trustList->issuerCrls, trustList->issuerCrlsSize,
                           context->trustedIssuerCrlDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    return retval;
}

UA_StatusCode
FileCertStore_getRejectedList(UA_CertificateGroup *certGroup, UA_ByteString **rejectedList,
                              size_t *rejectedListSize) {
    /* Check parameter */
    if (certGroup == NULL || rejectedList == NULL || rejectedListSize == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    FileCertStore *context = (FileCertStore *)certGroup->context;

    return loadList(rejectedList, rejectedListSize, context->rejectedCertDir);
}

UA_StatusCode
FileCertStore_getCertificates(UA_CertificateGroup *certGroup, UA_ByteString **certificates,
                              size_t *certificatesSize) {
    /* Check parameter */
    if (certGroup == NULL || certificates == NULL || certificatesSize == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    FileCertStore *context = (FileCertStore *)certGroup->context;

    return loadList(certificates, certificatesSize, context->certificateDir);
}

UA_StatusCode
FileCertStore_getPrivateKeys(UA_CertificateGroup *certGroup, UA_ByteString **privateKeys,
                             size_t *privateKeysSize) {
    /* Check parameter */
    if (certGroup == NULL || privateKeys == NULL || privateKeysSize == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    FileCertStore *context = (FileCertStore *)certGroup->context;

    return loadList(privateKeys, privateKeysSize, context->keyDir);
}

UA_StatusCode
FileCertStore_addToRejectedList(UA_CertificateGroup *certGroup, const UA_ByteString *certificate) {
    /* Check parameter */
    if(certGroup == NULL || certificate == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    FileCertStore *context = (FileCertStore *)certGroup->context;

    /* check duplicate certificate */
    UA_ByteString *rejectedList = NULL;
    size_t rejectedListLen = 0;
    retval = loadList(&rejectedList, &rejectedListLen, context->rejectedCertDir);
    if(retval != UA_STATUSCODE_GOOD) {
        return retval;
    }

    for(size_t idx = 0; idx < rejectedListLen; idx++) {
        if(UA_ByteString_equal(&rejectedList[idx], certificate)) {
            UA_Array_delete(rejectedList, rejectedListLen, &UA_TYPES[UA_TYPES_BYTESTRING]);
            return UA_STATUSCODE_GOOD; /* certificate already exist */
        }
    }
    UA_Array_delete(rejectedList, rejectedListLen, &UA_TYPES[UA_TYPES_BYTESTRING]);

    /* Create filename to store */
    char filename[FILENAME_MAX];
    retval = getCertFileName(context->rejectedCertDir, certificate, filename, FILENAME_MAX);
    if(retval != UA_STATUSCODE_GOOD) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Store data in file */
    return writeByteStringToFile(filename, certificate);
}

void
FileCertStore_clear(UA_CertificateGroup *certGroup) {
    /* check parameter */
    if (certGroup == NULL) {
        return;
    }

    UA_NodeId_clear(&certGroup->certificateGroupId);

    FileCertStore *context = (FileCertStore *)certGroup->context;
    if(context) {
        if(context->trustedCertDir)
            UA_free(context->trustedCertDir);
        if(context->trustedCrlDir)
            UA_free(context->trustedCrlDir);
        if(context->trustedIssuerCertDir)
            UA_free(context->trustedIssuerCertDir);
        if(context->trustedIssuerCrlDir)
            UA_free(context->trustedIssuerCrlDir);
        if(context->rejectedCertDir)
            UA_free(context->rejectedCertDir);
        if(context->certificateDir)
            UA_free(context->certificateDir);
        if(context->keyDir)
            UA_free(context->keyDir);
        if (context->rootDir) {
            UA_free(context->rootDir);
        }
        UA_free(context);
        certGroup->context = NULL;
    }
}

UA_StatusCode
FileCertStore_createRootDirectory(const UA_String *directory, const UA_NodeId *certificateGroupId,
                                  char** rootDir, size_t* rootDirLen) {
    char rootDirectory[PATH_MAX];
    *rootDir = NULL;
    *rootDirLen = 0;

    /* Set base directory */
    memset(rootDirectory, 0x00, PATH_MAX);
    if(directory != NULL) {
        if(directory->length >= PATH_MAX) {
            return UA_STATUSCODE_BADINTERNALERROR;
        }
        memcpy(rootDirectory, directory->data, directory->length);
    }
    else {
        if(getcwd(rootDirectory, PATH_MAX) == NULL) {
            return UA_STATUSCODE_BADINTERNALERROR;
        }
    }
    size_t rootDirectoryLen = strnlen(rootDirectory, PATH_MAX);

    /* Add pki directory */
    strncpy(&rootDirectory[rootDirectoryLen], "/pki/", PATH_MAX - rootDirectoryLen);
    rootDirectoryLen = strnlen(rootDirectory, PATH_MAX);

    /* Add Certificate Group Id */
    UA_NodeId applCertGroup = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId httpCertGroup = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP);
    UA_NodeId userTokenCertGroup = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP);

    if (UA_NodeId_equal(certificateGroupId, &applCertGroup)) {
        strncpy(&rootDirectory[rootDirectoryLen], "ApplCerts", PATH_MAX - rootDirectoryLen);
    }
    else if (UA_NodeId_equal(certificateGroupId, &httpCertGroup)) {
        strncpy(&rootDirectory[rootDirectoryLen], "HttpCerts", PATH_MAX - rootDirectoryLen);
    }
    else if (UA_NodeId_equal(certificateGroupId, &userTokenCertGroup)) {
        strncpy(&rootDirectory[rootDirectoryLen], "UserTokenCerts", PATH_MAX - rootDirectoryLen);
    }
    else {
        UA_String nodeIdStr;
        UA_String_init(&nodeIdStr);
        UA_NodeId_print(certificateGroupId, &nodeIdStr);
        strncpy(&rootDirectory[rootDirectoryLen], (char*)nodeIdStr.data, PATH_MAX - rootDirectoryLen);
        UA_String_clear(&nodeIdStr);
    }
    rootDirectoryLen = strnlen(rootDirectory, PATH_MAX);

    *rootDir = (char*)malloc(rootDirectoryLen+1);
    if (*rootDir == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    memcpy(*rootDir, rootDirectory, rootDirectoryLen+1);

    *rootDirLen = strnlen(*rootDir, PATH_MAX);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
FileCertStore_setupStorePath(char *directory, char *cwd, size_t cwdLen, char **out) {
    char path[PATH_MAX];
    size_t pathLen = 0;

    strncpy(path, cwd, PATH_MAX);
    pathLen = strnlen(path, PATH_MAX);

    strncpy(&path[pathLen], directory, PATH_MAX - pathLen);
    pathLen = strnlen(path, PATH_MAX);

    *out = strndup(path, pathLen+1);
    if(*out == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    mkpath(*out, 0777);
    return UA_STATUSCODE_GOOD;
}
