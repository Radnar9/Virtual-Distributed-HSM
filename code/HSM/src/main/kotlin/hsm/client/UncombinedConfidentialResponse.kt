package hsm.client

import confidential.ExtractedResponse
import vss.secretsharing.VerifiableShare

class UncombinedConfidentialResponse(
    viewID: Int,
    plainData: ByteArray,
    private val verifiableShares: List<List<VerifiableShare>> = emptyList(),
    private val sharedData: List<ByteArray> = emptyList()
) : ExtractedResponse(plainData, null) {

    init {
        setViewID(viewID)
    }

    fun getVerifiableShares(): List<List<VerifiableShare>> {
        return verifiableShares
    }

    fun getPlainData(): ByteArray {
        return this.content
    }

    fun getSharedData(): List<ByteArray> {
        return sharedData
    }
}
