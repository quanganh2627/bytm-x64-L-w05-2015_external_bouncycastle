/*
 * Copyright (C) 2010-2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <string.h>
#include "iaesni.h"
#include "AES.h"



#define BLOCK_SIZE (16)
/**
 * Function to check if hardware supports AESNI
 */
JNIEXPORT jint JNICALL Java_com_android_org_bouncycastle_crypto_paddings_PaddedBufferedBlockCipher_checkAesNI(JNIEnv *env, jobject thisObj)
{
   return check_for_aes_instructions();
}
/**
 * Function to call into AESNI assembly module
 */
JNIEXPORT jint JNICALL Java_com_android_org_bouncycastle_crypto_paddings_PaddedBufferedBlockCipher_aesNI
  (JNIEnv *env, jobject thisObj, jbyteArray inArray, jbyteArray keyArray, jbyteArray outArray,jbyteArray init_vector, jint buffLen, jint Enc, jint Keylen)
{
   //IV and input buffer

   jbyte * test_init_vector;

   jbyte * buffer;

   //Function pointer array for AES functions
   static void (*operation_ptr[3][2])(UCHAR *testVector,UCHAR *testResult,UCHAR *testKey,size_t numBlocks,UCHAR *IV) = {
       {intel_AES_dec128_CBC,intel_AES_enc128_CBC},
       {intel_AES_dec192_CBC,intel_AES_enc192_CBC},
       {intel_AES_dec256_CBC,intel_AES_enc256_CBC}};
   //Copy contents to local buffer
   buffer= (*env)->GetByteArrayElements(env, inArray, NULL);
   test_init_vector=(*env)->GetByteArrayElements(env,init_vector,NULL);
   jbyte *key=(*env)->GetByteArrayElements(env,keyArray,NULL);
   UCHAR *IV=(UCHAR*)test_init_vector;
   UCHAR *testVector = (UCHAR*)buffer;
   UCHAR *testResult = (UCHAR*)malloc(buffLen);
   UCHAR *testKey= (UCHAR*)key;
   //Number of blocks of Data
   int numBlocks=buffLen/BLOCK_SIZE;
   //Validate parameters
   if ((IV == NULL) || (testVector == NULL) || (testResult == NULL)
      || (testKey == NULL))
   {
       buffLen = 0;
       goto out;
   }
   //Make sure last bytes are not left out
   if(numBlocks%BLOCK_SIZE!=0)
   {
       numBlocks++;
   }
   //Initialize result array
   memset(testResult,0xee,buffLen);

   int index= ((Keylen>>3)-2) & (0x3);

   //Call AESNI assembly functions to perform our operation switch according to keysize(128,192,256)
   (*operation_ptr[index][Enc])(testVector, testResult, testKey, numBlocks, IV);

    //Copy back result to java object
    jbyte *result=(jbyte*)testResult;
    (*env)->SetByteArrayRegion(env, outArray, 0 , buffLen, result);

    //Free memory
out:
    if (testResult) free(testResult);

    if (buffer) (*env)->ReleaseByteArrayElements(env,inArray,buffer,0);

    if (key) (*env)->ReleaseByteArrayElements(env,keyArray,key,0);

    if (test_init_vector) {
        (*env)->ReleaseByteArrayElements(env,init_vector,test_init_vector,0);
    }

    return buffLen;
}

