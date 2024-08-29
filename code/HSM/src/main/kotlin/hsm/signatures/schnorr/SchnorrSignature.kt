package hsm.signatures.schnorr

import confidential.client.ConfidentialServiceProxy
import hsm.client.UncombinedConfidentialResponse
import hsm.communications.readByteArray
import hsm.communications.writeByteArray
import hsm.signatures.SignatureScheme
import org.bouncycastle.math.ec.ECPoint
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import java.io.*
import java.math.BigInteger
import java.util.*
import kotlin.system.exitProcess

class SchnorrSignature(
    private var sigma: ByteArray,
    private var signingPublicKey: ByteArray,
    private var randomPublicKey: ByteArray
) : Externalizable {

    // Identifier used to identify the corresponding signature scheme when deserializing a signature
    private val id = SignatureScheme.SCHNORR.ordinal

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

    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                out.writeInt(id)
                writeByteArray(out, sigma)
                writeByteArray(out, signingPublicKey)
                writeByteArray(out, randomPublicKey)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    override fun toString(): String {
        return """
            SchnorrSignature {
                sigma: ${BigInteger(sigma).toString(16).uppercase(Locale.getDefault())},
                signingPk: ${BigInteger(signingPublicKey).toString(16).uppercase(Locale.getDefault())},
                randomPk: ${BigInteger(randomPublicKey).toString(16).uppercase(Locale.getDefault())},
            }
        """.trimIndent()
    }

    companion object {
        fun buildFinalSignature(
            signatureResponse: UncombinedConfidentialResponse,
            schnorrSignatureScheme: SchnorrSignatureScheme,
            dataToSign: ByteArray,
            serviceProxy: ConfidentialServiceProxy,
        ): SchnorrSignature {
            lateinit var partialSignature: SchnorrPublicPartialSignature
            try {
                ByteArrayInputStream(signatureResponse.getPlainData()).use { bis ->
                    ObjectInputStream(bis).use { `in` ->
                        partialSignature = SchnorrPublicPartialSignature.deserialize(schnorrSignatureScheme, `in`)
                    }
                }
            } catch (e: Exception) { // IOException & ClassNotFoundException
                e.printStackTrace()
                serviceProxy.close()
                exitProcess(-1)
            }
            val signingPublicKey = schnorrSignatureScheme.decodePublicKey(partialSignature.getSigningPublicKey())

            val f = serviceProxy.currentF
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

        fun deserialize(serializedSignature: ByteArray): SchnorrSignature {
            ByteArrayInputStream(serializedSignature).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val signatureScheme = SignatureScheme.getScheme(`in`.readInt())
                    val sigma = readByteArray(`in`)
                    val signingPublicKey = readByteArray(`in`)
                    val randomPublicKey = readByteArray(`in`)
                    return SchnorrSignature(sigma, signingPublicKey, randomPublicKey)
                }
            }
        }
    }
}