package hsm.communications

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

class EncDecRequest(val indexId: String, val data: ByteArray, val operation: Operation) {
    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                out.writeUTF(indexId)
                writeByteArray(out, data)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return operation.ordinal.toByte().joinByteArray(serializedData)
    }

    companion object {
        fun deserialize(data: ByteArray): EncDecRequest {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    return EncDecRequest(`in`.readUTF(), readByteArray(`in`), Operation.EMPTY)
                }
            }
        }
    }
}