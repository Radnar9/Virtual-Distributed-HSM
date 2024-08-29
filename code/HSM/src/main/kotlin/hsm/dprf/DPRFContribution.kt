package hsm.dprf

import hsm.communications.deserializeBigInteger
import hsm.communications.serializeBigInteger
import java.io.*
import java.math.BigInteger


class DPRFContribution(
    val h: BigInteger,
    val c: BigInteger,
    val u: BigInteger
) {

    override fun toString(): String {
        return """
            DPRFContribution {
                h=${h.toString(16)},
                c=${c.toString(16)},
                u=${u.toString(16)}
            }
            """.trimIndent()
    }

    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                serializeBigInteger(h, out)
                serializeBigInteger(c, out)
                serializeBigInteger(u, out)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    fun writeExternal(out: ObjectOutput) {
        serializeBigInteger(h, out)
        serializeBigInteger(c, out)
        serializeBigInteger(u, out)
    }

    companion object {
        fun readExternal(`in`: ObjectInput): DPRFContribution {
            val h = deserializeBigInteger(`in`)
            val c = deserializeBigInteger(`in`)
            val u = deserializeBigInteger(`in`)
            return DPRFContribution(h, c, u)
        }
        fun deserialize(data: ByteArray): DPRFContribution {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    return readExternal(`in`)
                }
            }
        }
    }
}
