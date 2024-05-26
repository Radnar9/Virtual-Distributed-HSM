package hsm.communications

import hsm.Operation
import hsm.signatures.SignatureScheme
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

private val OPERATION = Operation.GENERATE_SIGNING_KEY

class KeyGenerationRequest(
    val privateKeyId: String,
    val signatureScheme: SignatureScheme,
) {
    fun serialize(withOperation: Boolean = true): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                writeByteArray(out, privateKeyId.toByteArray())
                writeByteArray(out, byteArrayOf(signatureScheme.ordinal.toByte()))
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        if (!withOperation) return serializedData

        return OPERATION.ordinal.toByte().joinByteArray(serializedData)
    }

    companion object {
        fun deserialize(data: ByteArray): KeyGenerationRequest {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val keyId = readByteArray(`in`).decodeToString()
                    val signatureScheme = SignatureScheme.getScheme(readByteArray(`in`)[0].toInt())
                    return KeyGenerationRequest(keyId, signatureScheme)
                }
            }
        }
    }
}