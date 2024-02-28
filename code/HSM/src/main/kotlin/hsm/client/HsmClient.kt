package hsm.client

import confidential.client.ConfidentialServiceProxy
import hsm.Operation.GENERATE_SIGNING_KEY
import hsm.communications.SignatureRequest
import hsm.signatures.*
import java.math.BigInteger
import kotlin.system.exitProcess

private fun generateSigningKey(keyIdentifier: String, serviceProxy: ConfidentialServiceProxy): UncombinedConfidentialResponse {
    val plainData = byteArrayOf(GENERATE_SIGNING_KEY.ordinal.toByte()) + keyIdentifier.toByteArray()
    return serviceProxy.invokeOrdered2(plainData) as UncombinedConfidentialResponse
}

private fun signData(
    privateKeyId: String,
    dataToSign: ByteArray,
    signatureScheme: SignatureScheme,
    serviceProxy: ConfidentialServiceProxy
): UncombinedConfidentialResponse {
    val signingReq = SignatureRequest(privateKeyId, dataToSign, signatureScheme).serialize()
    return serviceProxy.invokeOrdered2(signingReq) as UncombinedConfidentialResponse
}

// TODO: Develop the specific types according to PKCS#11 and serialize/deserialize the messages to communicate
fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: hsm.client.HsmClientKt <client id>")
        exitProcess(-1)
    }
    val clientId = args[0].toInt()

    val serversResponseHandler = ServersResponseHandlerWithoutCombine()
    val serviceProxy = ConfidentialServiceProxy(clientId, serversResponseHandler)

    // Generates a signing key (private key & public key)
    val signingPublicKeyBytes = generateSigningKey("slb", serviceProxy).plainData
    println("Signing public key: " + signingPublicKeyBytes.contentToString())


    // Sign a message (Schnorr signature)
    val schnorrSignatureScheme = SchnorrSignatureScheme()

    val privateKeyId = "slb"
    val dataToSign = "HSM".toByteArray()
    val signatureResponse = signData(privateKeyId, dataToSign, SignatureScheme.SCHNORR, serviceProxy)

    val finalSignature = buildFinalSignature(signatureResponse, schnorrSignatureScheme, signingPublicKeyBytes, dataToSign, serviceProxy)
    val isValid = schnorrSignatureScheme.verifySignature(
        dataToSign,
        schnorrSignatureScheme.decodePublicKey(finalSignature.getSigningPublicKey()),
        schnorrSignatureScheme.decodePublicKey(finalSignature.getRandomPublicKey()),
        BigInteger(finalSignature.getSigma())
    )
    println("The signature is ${if (isValid) "valid" else "invalid"}.")
    serviceProxy.close()
}
