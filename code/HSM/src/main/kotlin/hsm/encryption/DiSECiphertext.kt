package hsm.encryption

import hsm.communications.deserializeBigInteger
import hsm.communications.readByteArray
import hsm.communications.serializeBigInteger
import hsm.communications.writeByteArray
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.math.BigInteger
import java.util.*

class DiSECiphertext(
    val encryptorId: BigInteger,
    val alpha: ByteArray,
    val encryptedData: ByteArray,
) {

    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                serializeBigInteger(encryptorId, out)
                writeByteArray(out, alpha)
                writeByteArray(out, encryptedData)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    companion object {
         fun deserialize(data: ByteArray): DiSECiphertext {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val encryptorId = deserializeBigInteger(`in`)
                    val alpha = readByteArray(`in`)
                    val encryptedData = readByteArray(`in`)
                    return DiSECiphertext(encryptorId, alpha, encryptedData)
                }
            }
        }
    }

    override fun toString(): String {
        return """
            Ciphertext {
                encryptorId: $encryptorId,
                alpha: ${BigInteger(alpha).toString(16).uppercase(Locale.getDefault())},
                encryptedData: ${BigInteger(encryptedData).toString(16).uppercase(Locale.getDefault())},
            }
        """.trimIndent()
    }
}

class CiphertextMetadata(val encryptorId: BigInteger, val alpha: ByteArray) {
    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                serializeBigInteger(encryptorId, out)
                writeByteArray(out, alpha)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    companion object {
        fun deserialize(data: ByteArray): CiphertextMetadata {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val encryptorId = deserializeBigInteger(`in`)
                    val alpha = readByteArray(`in`)
                    return CiphertextMetadata(encryptorId, alpha)
                }
            }
        }
    }
}

fun DiSECiphertext.toCiphertextMetadata() = CiphertextMetadata(encryptorId, alpha)
