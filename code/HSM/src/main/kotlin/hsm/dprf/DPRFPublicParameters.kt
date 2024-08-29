package hsm.dprf

import hsm.communications.deserializeBigInteger
import hsm.communications.serializeBigInteger
import java.io.ObjectInput
import java.io.ObjectOutput
import java.math.BigInteger


class DPRFPublicParameters(
    private val generator: BigInteger,
    private val generatorCommitment: BigInteger,
    private val secretKeyShareCommitments: Map<BigInteger, BigInteger>,
) {
    fun getGenerator(): BigInteger {
        return generator
    }

    fun getGeneratorCommitment(): BigInteger {
        return generatorCommitment
    }

    fun getSecretKeyShareCommitmentOf(shareholder: BigInteger): BigInteger {
        return secretKeyShareCommitments[shareholder] ?: throw Exception("Share doesn't exist for shareholder: $shareholder")
    }

    fun writeExternal(out: ObjectOutput) {
        serializeBigInteger(generator, out)
        serializeBigInteger(generatorCommitment, out)
        serializeBigInteger(secretKeyShareCommitments.keys.first(), out)
        serializeBigInteger(secretKeyShareCommitments.values.first(), out)
    }

    companion object {
        fun readExternal(`in`: ObjectInput): DPRFPublicParameters {
            val generator = deserializeBigInteger(`in`)
            val generatorCommitment = deserializeBigInteger(`in`)
            val secretKeyShareShareholder = deserializeBigInteger(`in`)
            val secretKeyShareCommitment = deserializeBigInteger(`in`)
            return DPRFPublicParameters(generator, generatorCommitment, mapOf(secretKeyShareShareholder to secretKeyShareCommitment))
        }
    }

    override fun toString(): String {
        return "DPRFPublicParameters{generator=${generator.toString(16)},\ngeneratorCommitment=${generatorCommitment.toString(16)},\nsecretKeyShareCommitments=$secretKeyShareCommitments}"
    }
}
