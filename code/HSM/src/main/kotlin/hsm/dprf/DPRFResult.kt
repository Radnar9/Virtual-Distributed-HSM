package hsm.dprf

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

class DPRFResult(
    val contribution: DPRFContribution,
    val publicParameters: DPRFPublicParameters,
) {
    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                contribution.writeExternal(out)
                publicParameters.writeExternal(out)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    companion object {
        fun deserialize(data: ByteArray): DPRFResult {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val contribution = DPRFContribution.readExternal(`in`)
                    val publicParameters = DPRFPublicParameters.readExternal(`in`)
                    return DPRFResult(contribution, publicParameters)
                }
            }
        }
    }
}