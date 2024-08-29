package hsm.communications

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

class EncDecRequest(private val data: ByteArray, private val operation: Operation) {
    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                writeByteArray(out, data)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return operation.ordinal.toByte().joinByteArray(serializedData)
    }

    companion object {
        fun deserialize(data: ByteArray): ByteArray {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    return readByteArray(`in`)
                }
            }
        }
    }
}