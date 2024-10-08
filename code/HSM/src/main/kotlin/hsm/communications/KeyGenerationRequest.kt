package hsm.communications

import hsm.signatures.KeyScheme
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

private val OPERATION = Operation.GENERATE_SIGNING_KEY

class KeyGenerationRequest(
    val privateKeyId: String,
    val keyScheme: KeyScheme,
) {
    fun serialize(withOperation: Boolean = true): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                writeByteArray(out, privateKeyId.toByteArray())
                writeByteArray(out, byteArrayOf(keyScheme.ordinal.toByte()))
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
                    val keyScheme = KeyScheme.getScheme(readByteArray(`in`)[0].toInt())
                    return KeyGenerationRequest(keyId, keyScheme)
                }
            }
        }
    }
}