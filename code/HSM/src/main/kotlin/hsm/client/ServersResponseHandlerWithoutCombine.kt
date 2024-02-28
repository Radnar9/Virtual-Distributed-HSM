package hsm.client

import bftsmart.tom.core.messages.TOMMessage
import bftsmart.tom.util.ExtractedResponse
import confidential.ConfidentialMessage
import confidential.client.ClientConfidentialityScheme
import confidential.client.ServersResponseHandler
import vss.secretsharing.VerifiableShare
import java.util.*

class ServersResponseHandlerWithoutCombine : ServersResponseHandler() {
    private val responses: MutableMap<ByteArray, ConfidentialMessage> = HashMap()
    private val responseHashes: MutableMap<ConfidentialMessage, Int> = HashMap()

    override fun setClientConfidentialityScheme(confidentialityScheme: ClientConfidentialityScheme) {
        super.setClientConfidentialityScheme(confidentialityScheme)
    }

    override fun extractResponse(replies: Array<TOMMessage?>, sameContent: Int, lastReceived: Int): ExtractedResponse? {
        val lastMsg = replies[lastReceived]
        var response: ConfidentialMessage?
        val msgs: MutableMap<Int, LinkedList<ConfidentialMessage>> = HashMap()
        for (msg in replies) {
            if (msg == null) continue
            response = responses[msg.content]
            if (response == null) {
                logger.warn("Something went wrong while getting deserialized response from {}", msg.sender)
                continue
            }
            val responseHash = responseHashes[response]!!

            val msgList = msgs.computeIfAbsent(responseHash) { _ -> LinkedList() }
            msgList.add(response)
        }

        for (msgList in msgs.values) {
            if (msgList.size != sameContent) continue

            val firstMsg = msgList.first
            val plainData = firstMsg.plainData

            if (firstMsg.shares == null) {
                return UncombinedConfidentialResponse(lastMsg!!.viewID, plainData)
            }

            // This response has secret data
            val numSecrets = firstMsg.shares.size
            val verifiableShares = ArrayList<LinkedList<VerifiableShare>>(numSecrets)
            (0..<numSecrets).forEach { _ -> verifiableShares.add(LinkedList()) }
            msgList.forEach { confidentialMessage ->
                val sharesI = confidentialMessage.shares
                (0..<numSecrets).forEachIndexed { i, _ -> verifiableShares[i].add(sharesI[i]) }
            }

            val sharedData: List<ByteArray> = verifiableShares.map { secretI -> secretI.first.sharedData }
            val allVerifiableShares = verifiableShares.map { secretI -> secretI.map { verifiableShare -> verifiableShare } }

            return UncombinedConfidentialResponse(lastMsg!!.viewID, plainData, allVerifiableShares, sharedData)
        }
        logger.error("This should not happen. Did not found {} equivalent responses", sameContent)
        return null
    }

    override fun compare(o1: ByteArray, o2: ByteArray): Int {
        println(o1.size)
        println(o2.size)
        val response1 = responses.computeIfAbsent(o1) { serializedData: ByteArray? ->
            println("-> ${serializedData?.size}: ServersResponseHandlerWithoutCombine")
            ConfidentialMessage.deserialize(serializedData)
        }
//        val response1 = responses.computeIfAbsent(o1, ConfidentialMessage::deserialize)
        val response2 = responses.computeIfAbsent(o2, ConfidentialMessage::deserialize)
        if (response1 == null && response2 == null) return 0
        if (response1 == null) return 1
        if (response2 == null) return -1
        val hash1 = responseHashes.computeIfAbsent(response1, ConfidentialMessage::hashCode)
        val hash2 = responseHashes.computeIfAbsent(response2, ConfidentialMessage::hashCode)
        return hash1 - hash2
    }

    override fun reset() {
        responses.clear()
        responseHashes.clear()
    }
}
