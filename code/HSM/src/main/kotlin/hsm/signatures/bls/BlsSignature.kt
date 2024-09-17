package hsm.signatures.bls

import hsm.client.UncombinedConfidentialResponse
import hsm.communications.readByteArray
import hsm.communications.writeByteArray
import hsm.signatures.KeyScheme
import java.io.*
import java.math.BigInteger
import java.util.*

class BlsSignature(
    private var signature: ByteArray,
    private var signingPublicKey: ByteArray,
) : Externalizable {

    // Identifier used to identify the corresponding signature scheme when deserializing a signature
    private val id = KeyScheme.BLS.ordinal

    fun getSignature() = signature
    fun getSigningPublicKey() = signingPublicKey

    override fun writeExternal(out: ObjectOutput) {
        writeByteArray(out, signature)
        writeByteArray(out, signingPublicKey)
    }

    override fun readExternal(`in`: ObjectInput) {
        signature = readByteArray(`in`)
        signingPublicKey = readByteArray(`in`)
    }

    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                out.writeInt(id)
                writeByteArray(out, signature)
                writeByteArray(out, signingPublicKey)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    override fun toString(): String {
        return """
            BlsSignature {
                signature: ${BigInteger(signature).toString(16).uppercase(Locale.getDefault())},
                pk: ${BigInteger(signingPublicKey).toString(16).uppercase(Locale.getDefault())}
            }
        """.trimIndent()
    }

    companion object {
        fun buildFinalSignature(
            signatureResponse: UncombinedConfidentialResponse,
            blsSignatureScheme: BlsSignatureScheme,
            dataToSign: ByteArray,
        ): BlsSignature {
            val verifiableShares = signatureResponse.getVerifiableShares()[0]
            val partialSignaturesWithPubKeys = verifiableShares.associate {
                it.share.shareholder to deserialize(it.share.share.toByteArray())
            }

            val partialSignatures = partialSignaturesWithPubKeys.keys.associateWith { shareholder ->
                partialSignaturesWithPubKeys[shareholder]!!.signature
            }
            val partialPubKeys = partialSignaturesWithPubKeys.keys.associateWith { shareholder ->
                partialSignaturesWithPubKeys[shareholder]!!.signingPublicKey
            }

            val signature = blsSignatureScheme.combinePartialSignatures(partialSignatures, partialPubKeys, dataToSign)
            val publicKey = blsSignatureScheme.combinePartialPublicKeys(partialPubKeys)
            val blsSignature = BlsSignature(signature, publicKey)
            return blsSignature
        }

        fun buildFinalPublicKey(signatureResponse: UncombinedConfidentialResponse, blsSignatureScheme: BlsSignatureScheme): ByteArray {
            val verifiableShares = signatureResponse.getVerifiableShares()[0]
            val partialSignaturesWithPubKeys = verifiableShares.associate {
                it.share.shareholder to it.share.share.toByteArray()
            }

            val publicKey = blsSignatureScheme.combinePartialPublicKeys(partialSignaturesWithPubKeys)
            return publicKey
        }

        fun deserialize(data: ByteArray): BlsSignature {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val keyScheme = KeyScheme.getScheme(`in`.readInt())
                    val signature = readByteArray(`in`)
                    val signingPublicKey = readByteArray(`in`)
                    return BlsSignature(signature, signingPublicKey)
                }
            }
        }
    }
}