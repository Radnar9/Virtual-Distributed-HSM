package hsm.signatures

import confidential.client.ConfidentialServiceProxy
import hsm.client.UncombinedConfidentialResponse
import hsm.communications.readByteArray
import hsm.communications.writeByteArray
import org.bouncycastle.math.ec.ECPoint
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import java.io.*
import kotlin.system.exitProcess

class SchnorrSignature(
    private var sigma: ByteArray,
    private var signingPublicKey: ByteArray,
    private var randomPublicKey: ByteArray
) : Externalizable {

    fun getSigma() = sigma

    fun getSigningPublicKey() = signingPublicKey

    fun getRandomPublicKey() = randomPublicKey

    override fun writeExternal(out: ObjectOutput) {
        writeByteArray(out, sigma)
        writeByteArray(out, signingPublicKey)
        writeByteArray(out, randomPublicKey)
    }

    override fun readExternal(`in`: ObjectInput) {
        sigma = readByteArray(`in`)
        signingPublicKey = readByteArray(`in`)
        randomPublicKey = readByteArray(`in`)
    }
}

fun buildFinalSignature(
    signatureResponse: UncombinedConfidentialResponse,
    schnorrSignatureScheme: SchnorrSignatureScheme,
    signingPublicKeyBytes: ByteArray,
    dataToSign: ByteArray,
    serviceProxy: ConfidentialServiceProxy,
): SchnorrSignature {
    lateinit var partialSignature: PublicPartialSignature
    try {
        ByteArrayInputStream(signatureResponse.plainData).use { bis ->
            ObjectInputStream(bis).use { `in` ->
                partialSignature = PublicPartialSignature.deserialize(schnorrSignatureScheme, `in`)
            }
        }
    } catch (e: Exception) { // IOException & ClassNotFoundException
        e.printStackTrace()
        serviceProxy.close()
        exitProcess(-1)
    }
    val signingPublicKey = schnorrSignatureScheme.decodePublicKey(signingPublicKeyBytes)

    val f = 1
    val signingKeyCommitment: EllipticCurveCommitment = partialSignature.getSigningKeyCommitment()
    val randomKeyCommitment: EllipticCurveCommitment = partialSignature.getRandomKeyCommitment()
    val randomPublicKey: ECPoint = partialSignature.getRandomPublicKey()
    val verifiableShares = signatureResponse.getVerifiableShares()[0]
    val partialSignatures = verifiableShares.map { it.share }.toTypedArray()

    val signature: SchnorrSignature = schnorrSignatureScheme.combinePartialSignatures(
        f,
        dataToSign,
        signingKeyCommitment,
        randomKeyCommitment,
        signingPublicKey,
        randomPublicKey,
        *partialSignatures
    )

    return signature
}