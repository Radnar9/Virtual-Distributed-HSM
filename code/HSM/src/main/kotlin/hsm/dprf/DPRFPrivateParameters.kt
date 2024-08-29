package hsm.dprf

import java.math.BigInteger


class DPRFPrivateParameters(private val secretKeyShare: BigInteger) {
    fun getSecretKeyShare(): BigInteger {
        return secretKeyShare
    }

    override fun toString(): String {
        return "DPRFPrivateParameters{secretKeyShare=$secretKeyShare}"
    }
}
