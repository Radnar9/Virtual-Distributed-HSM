package hsm.client

import confidential.ConfidentialExtractedResponse
import vss.secretsharing.VerifiableShare

class UncombinedConfidentialResponse(
    viewID: Int,
    plainData: ByteArray,
    private val verifiableShares: List<List<VerifiableShare>> = emptyList(),
    private val sharedData: List<ByteArray> = emptyList()
) : ConfidentialExtractedResponse(viewID, plainData, null, null) {

    fun getVerifiableShares(): List<List<VerifiableShare>> {
        return verifiableShares
    }

    fun getSharedData(): List<ByteArray> {
        return sharedData
    }
}
