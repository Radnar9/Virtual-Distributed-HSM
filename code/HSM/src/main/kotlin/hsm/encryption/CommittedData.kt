package hsm.encryption

import hsm.communications.readByteArray
import hsm.communications.writeByteArray
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

class CommittedData(val alpha: ByteArray, val p: ByteArray) {
    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                writeByteArray(out, alpha)
                writeByteArray(out, p)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    companion object {
        fun deserialize(data: ByteArray): CommittedData {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val alpha = readByteArray(`in`)
                    val p = readByteArray(`in`)
                    return CommittedData(alpha, p)
                }
            }
        }
    }
}