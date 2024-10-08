/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class hsm_signatures_bls_BlsSignatureScheme */

#ifndef _Included_hsm_signatures_bls_BlsSignatureScheme
#define _Included_hsm_signatures_bls_BlsSignatureScheme
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     hsm_signatures_bls_BlsSignatureScheme
 * Method:    initialize
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_hsm_signatures_bls_BlsSignatureScheme_initialize
  (JNIEnv *, jobject, jint);

/*
 * Class:     hsm_signatures_bls_BlsSignatureScheme
 * Method:    getOrderBytes
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_hsm_signatures_bls_BlsSignatureScheme_getOrderBytes
  (JNIEnv *, jobject);

/*
 * Class:     hsm_signatures_bls_BlsSignatureScheme
 * Method:    computeKeyPair
 * Signature: ()[[B
 */
JNIEXPORT jobjectArray JNICALL Java_hsm_signatures_bls_BlsSignatureScheme_computeKeyPair
  (JNIEnv *, jobject);

/*
 * Class:     hsm_signatures_bls_BlsSignatureScheme
 * Method:    computePublicKey
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_hsm_signatures_bls_BlsSignatureScheme_computePublicKey
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     hsm_signatures_bls_BlsSignatureScheme
 * Method:    computeSignature
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_hsm_signatures_bls_BlsSignatureScheme_computeSignature
  (JNIEnv *, jobject, jbyteArray, jbyteArray);

/*
 * Class:     hsm_signatures_bls_BlsSignatureScheme
 * Method:    computeVerification
 * Signature: ([B[B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_hsm_signatures_bls_BlsSignatureScheme_computeVerification
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     hsm_signatures_bls_BlsSignatureScheme
 * Method:    interpolatePartialSignatures
 * Signature: ([[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_hsm_signatures_bls_BlsSignatureScheme_interpolatePartialSignatures
  (JNIEnv *, jobject, jobjectArray);

/*
 * Class:     hsm_signatures_bls_BlsSignatureScheme
 * Method:    interpolatePartialPublicKeys
 * Signature: ([[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_hsm_signatures_bls_BlsSignatureScheme_interpolatePartialPublicKeys
  (JNIEnv *, jobject, jobjectArray);

#ifdef __cplusplus
}
#endif
#endif
