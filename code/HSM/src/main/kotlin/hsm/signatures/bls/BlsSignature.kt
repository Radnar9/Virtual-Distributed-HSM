package hsm.signatures.bls

import bls.BLS
import hsm.client.UncombinedConfidentialResponse
import hsm.communications.readByteArray
import hsm.communications.writeByteArray
import java.io.*

class BlsSignature(
    private var signature: ByteArray,
    private var signingPublicKey: ByteArray,
) : Externalizable {

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
                writeByteArray(out, signature)
                writeByteArray(out, signingPublicKey)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    companion object {
        fun buildFinalSignature(
            signatureResponse: UncombinedConfidentialResponse,
            blsSignatureScheme: BLS,
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
            return BlsSignature(signature, publicKey)
        }

        fun buildFinalPublicKey(signatureResponse: UncombinedConfidentialResponse, blsSignatureScheme: BLS): ByteArray {
            val verifiableShares = signatureResponse.getVerifiableShares()[0]
            val partialSignaturesWithPubKeys = verifiableShares.associate {
                it.share.shareholder to it.share.share.toByteArray()
            }

            val publicKey = blsSignatureScheme.combinePartialPublicKeys(partialSignaturesWithPubKeys)
            return publicKey
        }

        private fun deserialize(data: ByteArray): BlsSignature {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val signature = readByteArray(`in`)
                    val signingPublicKey = readByteArray(`in`)
                    return BlsSignature(signature, signingPublicKey)
                }
            }
        }
    }
}