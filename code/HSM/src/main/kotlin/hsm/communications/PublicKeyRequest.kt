package hsm.communications

import hsm.signatures.KeyScheme
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

private val OPERATION = Operation.GET_PUBLIC_KEY

class PublicKeyRequest(val indexId: String, val keyScheme: KeyScheme) {
    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                out.writeUTF(indexId)
                writeByteArray(out, byteArrayOf(keyScheme.ordinal.toByte()))
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return OPERATION.ordinal.toByte().joinByteArray(serializedData)
    }

    companion object {
        fun deserialize(data: ByteArray): PublicKeyRequest {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    return PublicKeyRequest(`in`.readUTF(), KeyScheme.getScheme(readByteArray(`in`)[0].toInt()))
                }
            }
        }
    }
}