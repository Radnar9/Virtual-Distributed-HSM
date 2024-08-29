package hsm.dprf

import java.math.BigInteger


class DPRFParameters(
    val publicParameters: DPRFPublicParameters,
    private val privateParameters: Map<BigInteger, DPRFPrivateParameters>
) {
    fun getPrivateParameterOf(shareholder: BigInteger): DPRFPrivateParameters {
        return privateParameters[shareholder] ?: throw Exception("No private parameter for shareholder: $shareholder")
    }

    override fun toString(): String {
        return "DPRFParameters{publicParameters=$publicParameters,\nprivateParameters=$privateParameters}"
    }
}