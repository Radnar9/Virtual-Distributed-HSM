package hsm.client

import hsm.signatures.bls.BlsSignatureScheme
import confidential.EllipticCurveConstants
import confidential.client.ConfidentialServiceProxy
import hsm.communications.*
import hsm.dprf.DPRFPublicParameters
import hsm.dprf.DPRFResult
import hsm.encryption.DiSE
import hsm.encryption.toCiphertextMetadata
import hsm.signatures.schnorr.SchnorrSignature
import hsm.signatures.schnorr.SchnorrSignatureScheme
import hsm.signatures.SignatureScheme
import hsm.signatures.bls.BlsSignature
import java.io.ByteArrayInputStream
import java.io.ObjectInputStream
import java.math.BigInteger


class ClientAPI(private val clientId: Int) {
    private val serversResponseHandler = ServersResponseHandlerWithoutCombine(clientId)
    private val serviceProxy = ConfidentialServiceProxy(clientId, serversResponseHandler)
    private val currentF = serviceProxy.currentF

    private val schnorrScheme = SchnorrSignatureScheme()
    private val blsScheme = BlsSignatureScheme(currentF)
    private val dise = DiSE(clientId.toBigInteger(), currentF, EllipticCurveConstants.secp256r1.PARAMETERS, secretKey = BigInteger("7f348d53ba8e43bba3585746af343fe1", 16))

    fun generateKey(indexId: String, signatureScheme: SignatureScheme): ByteArray {
        val keyGenRequest = KeyGenerationRequest(indexId, signatureScheme)
        val response = serviceProxy.invokeOrderedOperation(keyGenRequest.serialize()) as UncombinedConfidentialResponse
        val publicKey = when (signatureScheme) {
            SignatureScheme.SCHNORR -> response.getPlainData()
            SignatureScheme.BLS -> BlsSignature.buildFinalPublicKey(response, blsScheme)
        }
        return publicKey
    }

    fun signData(indexId: String, signatureScheme: SignatureScheme, data: ByteArray): ByteArray {
        val signingReq = SignatureRequest(indexId, data, signatureScheme)
        val response = serviceProxy.invokeOrderedOperation(signingReq.serialize()) as UncombinedConfidentialResponse
        val finalSignature = when (signatureScheme) {
            SignatureScheme.SCHNORR -> SchnorrSignature.buildFinalSignature(response, schnorrScheme, data, serviceProxy).serialize()
            SignatureScheme.BLS -> BlsSignature.buildFinalSignature(response, blsScheme, data).serialize()
        }
        return finalSignature
    }

    fun encryptData(data: ByteArray): ByteArray? {
        val committedData = dise.commitData(data)
        val encDecRequest = EncDecRequest(committedData.serialize(), Operation.ENCRYPT)
        val response = serviceProxy.invokeOrderedOperation(encDecRequest.serialize()) as UncombinedConfidentialResponse

        val partialResults = response.getVerifiableShares()[0].associate { res ->
            res.share.shareholder to DPRFResult.deserialize(res.share.share.toByteArray())
        }
        val contributions = partialResults.map { it.value.contribution }.toTypedArray()
        val commitmentsMap = partialResults.map { it.key to it.value.publicParameters.getSecretKeyShareCommitmentOf(it.key) }.toMap()
        val firstPublicParameters = partialResults.values.first().publicParameters
        val dprfPublicParameters = DPRFPublicParameters(
            firstPublicParameters.getGenerator(),
            firstPublicParameters.getGeneratorCommitment(),
            commitmentsMap,
        )
        val encEvalInput = BigInteger(1, "$clientId".toByteArray().plus(committedData.alpha))
        val ciphertext = dise.encrypt(
            data,
            committedData,
            encEvalInput,
            dprfPublicParameters,
            partialResults.keys.toTypedArray(),
            contributions,
        )
        return ciphertext
    }

    fun decryptData(ciphertext: ByteArray): ByteArray? {
        val parsedCiphertext = dise.parseEncryptedData(ciphertext)
        val ciphertextMetadata = parsedCiphertext.toCiphertextMetadata()
        val evalInput = BigInteger(1, "${parsedCiphertext.encryptorId}".toByteArray().plus(parsedCiphertext.alpha))

        val encDecRequest = EncDecRequest(ciphertextMetadata.serialize(), Operation.DECRYPT)
        val response = serviceProxy.invokeOrderedOperation(encDecRequest.serialize()) as UncombinedConfidentialResponse

        val partialResults = response.getVerifiableShares()[0].associate { res ->
            res.share.shareholder to DPRFResult.deserialize(res.share.share.toByteArray())
        }
        val contributions = partialResults.map { it.value.contribution }.toTypedArray()
        val commitmentsMap = partialResults.map { it.key to it.value.publicParameters.getSecretKeyShareCommitmentOf(it.key) }.toMap()
        val firstPublicParameters = partialResults.values.first().publicParameters
        val dprfPublicParameters = DPRFPublicParameters(
            firstPublicParameters.getGenerator(),
            firstPublicParameters.getGeneratorCommitment(),
            commitmentsMap,
        )
        val decryptedMessage = dise.decrypt(
            parsedCiphertext,
            evalInput,
            dprfPublicParameters,
            partialResults.keys.toTypedArray(),
            contributions,
        )
        return decryptedMessage
    }

    fun validateSignature(signature: ByteArray, data: ByteArray): Boolean {
        val signatureScheme = deserializeSignatureScheme(signature)
        val validity = when (signatureScheme) {
            SignatureScheme.SCHNORR -> {
                val finalSignature = SchnorrSignature.deserialize(signature)
                schnorrScheme.verifySignature(
                    data,
                    schnorrScheme.decodePublicKey(finalSignature.getSigningPublicKey()),
                    schnorrScheme.decodePublicKey(finalSignature.getRandomPublicKey()),
                    BigInteger(finalSignature.getSigma())
                )
            }
            SignatureScheme.BLS -> {
                val finalSignature = BlsSignature.deserialize(signature)
                blsScheme.verifySignature(
                    finalSignature.getSignature(),
                    data,
                    finalSignature.getSigningPublicKey()
                )
            }
        }
        return validity
    }

    private data class KeyData(val indexId: String, val publicKey: String, val signatureScheme: SignatureScheme)
    fun availableKeys() {
        val operationBytes = byteArrayOf(Operation.AVAILABLE_KEYS.ordinal.toByte())
        val response = serviceProxy.invokeOrderedOperation(operationBytes) as UncombinedConfidentialResponse

        val keys = deserializeAvailableKeys(response.getVerifiableShares()[0][0].share.share.toByteArray())
        println("----| Available Keys: ${keys.size} |----\n")
        for (key in keys) {
            println("""
                indexId:         ${key.indexId}
                public key:      ${key.publicKey}
                signatureScheme: ${key.signatureScheme}
                
            """.trimIndent())
        }
    }

    fun commands() {
        println("----| Available Commands |----")
        println("""
            hsm.client.HsmClientKt                      keyGen           <client id> <index key id> <schnorr or bls>
                                                        sign             <client id> <index key id> <schnorr or bls> <data>
                                                        enc              <client id> <data>
                                                        dec              <client id> <ciphertext>
                                                        valSign          <client id> <signature> <initial data>
                                                        availableKeys    <client id>
                                                        help
                                   
            hsm.client.ThroughputLatencyEvaluationKt    keyGen    <initial client id> <number of clients> <number of reps> <index key id> <schnorr or bls>
                                                        sign      <initial client id> <number of clients> <number of reps> <index key id> <schnorr or bls> <data>
                                                        encDec    <initial client id> <number of clients> <number of reps> <data>
                                                        all       <initial client id> <number of clients> <number of reps>
        """.trimIndent())
    }

    fun close() {
        serviceProxy.close()
    }

    /**
     * Deserializes the first integer from the signature to discover the signature's scheme.
     */
    private fun deserializeSignatureScheme(signatureBytes: ByteArray): SignatureScheme {
        ByteArrayInputStream(signatureBytes).use { bis ->
            ObjectInputStream(bis).use { `in` ->
                val signatureScheme = SignatureScheme.getScheme(`in`.readInt())
                return signatureScheme
            }
        }
    }

    private fun deserializeAvailableKeys(responseBytes: ByteArray): List<KeyData> {
        ByteArrayInputStream(responseBytes).use { bis ->
            ObjectInputStream(bis).use { `in` ->
                val size = `in`.readInt()
                val list = ArrayList<KeyData>(size)
                for (i in 0..<size) {
                    val indexId = `in`.readUTF()
                    val publicKey = readByteArray(`in`)
                    val signatureScheme = SignatureScheme.getScheme(`in`.readInt())
                    list.add(KeyData(indexId, BigInteger(publicKey).toString(16), signatureScheme))
                }
                return list
            }
        }
    }
}

