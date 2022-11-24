#include "secrets.hpp"

#include <jni.h>

#include "sha256.hpp"
#include "sha256.cpp"

/* Copyright (c) 2020-present Klaxit SAS
*
* Permission is hereby granted, free of charge, to any person
* obtaining a copy of this software and associated documentation
* files (the "Software"), to deal in the Software without
* restriction, including without limitation the rights to use,
* copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the
* Software is furnished to do so, subject to the following
* conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
* OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
* HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
* OTHER DEALINGS IN THE SOFTWARE.
*/

char *customDecode(char *str) {
    /* Add your own logic here
    * To improve your key security you can encode it before to integrate it in the app.
    * And then decode it with your own logic in this function.
    */
    int c = 18;
    int l = strlen(str);
    const char *alpha[2] = { "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"};
    int i;
    for (i = 0; i < l; i++)
    {
        if (!isalpha(str[i]))
            continue;
        if (isupper(str[i]))
            str[i] = alpha[1][((int)(tolower(str[i]) - 'a') + c) % 26];
        else
            str[i] = alpha[0][((int)(tolower(str[i]) - 'a') + c) % 26];
    }
    return str;
}

jstring getOriginalKey(
        char *obfuscatedSecret,
        int obfuscatedSecretSize,
        jstring obfuscatingJStr,
        JNIEnv *pEnv) {

    // Get the obfuscating string SHA256 as the obfuscator
    const char *obfuscatingStr = pEnv->GetStringUTFChars(obfuscatingJStr, NULL);
    char buffer[2 * SHA256::DIGEST_SIZE + 1];

    sha256(obfuscatingStr, buffer);
    const char *obfuscator = buffer;

    // Apply a XOR between the obfuscated key and the obfuscating string to get original string
    char out[obfuscatedSecretSize + 1];
    for (int i = 0; i < obfuscatedSecretSize; i++) {
        out[i] = obfuscatedSecret[i] ^ obfuscator[i % strlen(obfuscator)];
    }

    // Add string terminal delimiter
    out[obfuscatedSecretSize] = 0x0;

    // (Optional) To improve key security
    return pEnv->NewStringUTF(customDecode(out));
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_auth_Secrets_getPassWord(
        JNIEnv *pEnv,
        jobject pThis,
        jstring packageName) {
    char obfuscatedSecret[] = { 0x6c, 0x2d, 0x52, 0x64, 0x67, 0x31, 0x1a, 0x42, 0x5b, 0x51, 0x46, 0x5f, 0xf, 0x5d, 0x5b, 0x43, 0x21, 0x63, 0x30, 0x56, 0xd, 0x75, 0x1b, 0x5a, 0x61, 0x5c, 0x79, 0x45, 0x5, 0x3e, 0x40, 0x2b, 0x42, 0xc, 0x1b, 0x1a, 0x26, 0x6b, 0x20, 0x15, 0x60, 0x7a, 0x2a, 0x2, 0x66, 0x2f, 0xf, 0x9, 0x78, 0x78, 0x46, 0x2c, 0x47, 0x73, 0x1f, 0xb, 0x77, 0x42, 0x72, 0x62, 0x4b, 0x75, 0x7f, 0xb, 0x43, 0x0, 0x69, 0x50, 0x6a, 0x56, 0x9, 0x47, 0x66, 0x4, 0xf, 0x7a, 0x44, 0x52, 0x58, 0xd, 0x15, 0x6e, 0x3a, 0x4b, 0x54, 0x1d, 0x10, 0xa, 0x4d, 0x72, 0xf, 0x1, 0x1c, 0x4f, 0x5f, 0x2a, 0x43, 0x1b, 0x5b, 0x4d };
    return getOriginalKey(obfuscatedSecret, sizeof(obfuscatedSecret), packageName, pEnv);
}