package hsm.communications

import hsm.signatures.KeyScheme
import java.io.*

private val OPERATION = Operation.SIGN_DATA

class SignatureRequest(
    val privateKeyId: String,
    val dataToSign: ByteArray,
    val keyScheme: KeyScheme,
) {
    fun serialize(withOperation: Boolean = true): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                writeByteArray(out, privateKeyId.toByteArray())
                writeByteArray(out, dataToSign)
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
        fun deserialize(data: ByteArray): SignatureRequest {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val keyId = readByteArray(`in`).decodeToString()
                    val dataToSign = readByteArray(`in`)
                    val keyScheme = KeyScheme.getScheme(readByteArray(`in`)[0].toInt())
                    return SignatureRequest(keyId, dataToSign, keyScheme)
                }
            }
        }
    }
}
