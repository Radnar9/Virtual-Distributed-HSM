package hsm.client

import bls.BLS
import confidential.client.ConfidentialServiceProxy
import hsm.communications.KeyGenerationRequest
import hsm.communications.SignatureRequest
import hsm.signatures.*
import hsm.signatures.bls.BlsSignature
import java.math.BigInteger
import kotlin.system.exitProcess

private fun generateSigningKey(
    keyIdentifier: String,
    signatureScheme: SignatureScheme,
    serviceProxy: ConfidentialServiceProxy
): UncombinedConfidentialResponse {
    val keyGenRequest = KeyGenerationRequest(keyIdentifier, signatureScheme)
    return serviceProxy.invokeOrderedOperation(keyGenRequest.serialize()) as UncombinedConfidentialResponse
}

private fun signData(
    privateKeyId: String,
    dataToSign: ByteArray,
    signatureScheme: SignatureScheme,
    serviceProxy: ConfidentialServiceProxy
): UncombinedConfidentialResponse {
    val signingReq = SignatureRequest(privateKeyId, dataToSign, signatureScheme)
    return serviceProxy.invokeOrderedOperation(signingReq.serialize()) as UncombinedConfidentialResponse
}

// TODO: Develop the specific types according to PKCS#11 and serialize/deserialize the messages to communicate
fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: hsm.client.HsmClientKt <client id>")
        exitProcess(-1)
    }
    val clientId = args[0].toInt()

    val serversResponseHandler = ServersResponseHandlerWithoutCombine(clientId)
    val serviceProxy = ConfidentialServiceProxy(clientId, serversResponseHandler)

    val blsSignatureScheme = BLS(1)

    // Generates a Schnorr signing key (private key & public key)
    val schnorrPrivateKeyId = "schnorr"
    val schnorrSigningKeyResponse = generateSigningKey(schnorrPrivateKeyId, SignatureScheme.SCHNORR, serviceProxy)
    val schnorrPublicKey = schnorrSigningKeyResponse.getPlainData()
    println("Schnorr signing public key: ${BigInteger(schnorrPublicKey).toString(16)}\n")

    // Generates a BLS signing key (private key & public key)
    val blsPrivateKeyId = "bls"
    val blsSigningKeyResponse = generateSigningKey(blsPrivateKeyId, SignatureScheme.BLS, serviceProxy)
    val blsPublicKey = BlsSignature.buildFinalPublicKey(blsSigningKeyResponse, blsSignatureScheme)
    println("BLS signing public key: ${BigInteger(blsPublicKey).toString(16)}\n")


    // Sign a message (Schnorr signature)
    val schnorrSignatureScheme = SchnorrSignatureScheme()

    val dataToSign = "HSM".toByteArray()
    val signatureResponse = signData(schnorrPrivateKeyId, dataToSign, SignatureScheme.SCHNORR, serviceProxy)

    val finalSignature = SchnorrSignature.buildFinalSignature(
        signatureResponse,
        schnorrSignatureScheme,
        dataToSign,
        serviceProxy
    )

    val isValid = schnorrSignatureScheme.verifySignature(
        dataToSign,
        schnorrSignatureScheme.decodePublicKey(finalSignature.getSigningPublicKey()),
        schnorrSignatureScheme.decodePublicKey(finalSignature.getRandomPublicKey()),
        BigInteger(finalSignature.getSigma())
    )
    println("Combined Schnorr Signature: ${BigInteger(finalSignature.getSigma()).toString(16)}")
    println("The Schnorr signature is ${if (isValid) "valid" else "invalid"}.\n")

    // Sign a message (BLS signature)
    val message = "BLSSignatureTest".toByteArray()
    val blsSignatureResponse = signData(blsPrivateKeyId, message, SignatureScheme.BLS, serviceProxy)

    val blsSignature = BlsSignature.buildFinalSignature(
        blsSignatureResponse,
        blsSignatureScheme,
        message,
    )
    println("Combined BLS Signature: ${BigInteger(blsSignature.getSignature()).toString(16)}")
    println("Combined BLS Public Key: ${BigInteger(blsSignature.getSigningPublicKey()).toString(16)}")

    val isValidBlsSignature = blsSignatureScheme.verify(blsSignature.getSignature(), message, blsSignature.getSigningPublicKey())
    println("The BLS signature is ${if (isValidBlsSignature) "valid" else "invalid"}.")

    serviceProxy.close()
}
