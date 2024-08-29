package hsm.client

import confidential.EllipticCurveConstants
import hsm.signatures.bls.BlsSignatureScheme
import confidential.client.ConfidentialServiceProxy
import hsm.communications.Operation
import hsm.communications.EncDecRequest
import hsm.communications.KeyGenerationRequest
import hsm.communications.SignatureRequest
import hsm.dprf.DPRFPublicParameters
import hsm.dprf.DPRFResult
import hsm.encryption.DiSE
import hsm.encryption.toCiphertextMetadata
import hsm.signatures.*
import hsm.signatures.bls.BlsSignature
import hsm.signatures.schnorr.SchnorrSignature
import hsm.signatures.schnorr.SchnorrSignatureScheme
import java.math.BigInteger
import kotlin.math.pow
import kotlin.math.sqrt
import kotlin.system.exitProcess
import kotlin.system.measureTimeMillis

private fun generateSigningKey(
    keyIdentifier: String,
    signatureScheme: SignatureScheme,
    serviceProxy: ConfidentialServiceProxy
): UncombinedConfidentialResponse {
    val keyGenRequest = KeyGenerationRequest(keyIdentifier, signatureScheme)
    return serviceProxy.invokeOrderedOperation(keyGenRequest.serialize()) as UncombinedConfidentialResponse
}

private fun signData(
    privateKeyId: String,
    dataToSign: ByteArray,
    signatureScheme: SignatureScheme,
    serviceProxy: ConfidentialServiceProxy
): UncombinedConfidentialResponse {
    val signingReq = SignatureRequest(privateKeyId, dataToSign, signatureScheme)
    return serviceProxy.invokeOrderedOperation(signingReq.serialize()) as UncombinedConfidentialResponse
}

private fun encryptDecryptData(
    data: ByteArray,
    operation: Operation,
    serviceProxy: ConfidentialServiceProxy
): UncombinedConfidentialResponse {
    val encDecRequest = EncDecRequest(data, operation)
    return serviceProxy.invokeOrderedOperation(encDecRequest.serialize()) as UncombinedConfidentialResponse
}


fun main(args: Array<String>) {
    if (args.isEmpty() || args.size < 3) {
        println("Usage: hsm.client.HsmClientKt <client id> <op> <times>")
        exitProcess(-1)
    }
    val clientId = args[0].toInt()
    val op = args[1]
    val times = args[2].toInt()

    val serversResponseHandler = ServersResponseHandlerWithoutCombine(clientId)
    val serviceProxy = ConfidentialServiceProxy(clientId, serversResponseHandler)

    val schnorrSignatureScheme = SchnorrSignatureScheme()
    val blsSignatureScheme = BlsSignatureScheme(serviceProxy.currentF)
    val dise = DiSE(clientId.toBigInteger(), serviceProxy.currentF, EllipticCurveConstants.secp256r1.PARAMETERS)

    when (op) {
        "all" -> testAllFeatures(clientId.toBigInteger(), schnorrSignatureScheme, blsSignatureScheme, dise, serviceProxy)
        "skey" -> testSchnorrKeyPairGenLatency(times, serviceProxy)
        "bkey" -> testBLSKeyPairGenLatency(times, serviceProxy)
        "ssign" -> testSchnorrSignatureLatency(times, schnorrSignatureScheme, serviceProxy)
        "bsign" -> testBLSSignatureLatency(times, blsSignatureScheme, serviceProxy)
        "enc" -> testEncryptionLatency(times, clientId.toBigInteger(), dise, serviceProxy)
    }

    serviceProxy.close()
}


fun testAllFeatures(clientId: BigInteger, schnorrSignatureScheme: SchnorrSignatureScheme, blsSignatureScheme: BlsSignatureScheme, dise: DiSE, serviceProxy: ConfidentialServiceProxy) {
    // Generates a Schnorr signing key (private key & public key)
    val schnorrPrivateKeyId = "schnorr"
    val schnorrSigningKeyResponse = generateSigningKey(schnorrPrivateKeyId, SignatureScheme.SCHNORR, serviceProxy)
    val schnorrPublicKey = schnorrSigningKeyResponse.getPlainData()
    println("Schnorr signing public key: ${BigInteger(schnorrPublicKey).toString(16)}\n")

    // Generates a BLS signing key (private key & public key)
    val blsPrivateKeyId = "bls"
    val blsSigningKeyResponse = generateSigningKey(blsPrivateKeyId, SignatureScheme.BLS, serviceProxy)
    val blsPublicKey = BlsSignature.buildFinalPublicKey(blsSigningKeyResponse, blsSignatureScheme)
    println("BLS signing public key: ${BigInteger(blsPublicKey).toString(16)}\n")


    // Sign a message (Schnorr signature)
//    val schnorrSignatureScheme = SchnorrSignatureScheme()

    val dataToSign = "HSM".toByteArray()
    val signatureResponse = signData(schnorrPrivateKeyId, dataToSign, SignatureScheme.SCHNORR, serviceProxy)

    val finalSignature = SchnorrSignature.buildFinalSignature(
        signatureResponse,
        schnorrSignatureScheme,
        dataToSign,
        serviceProxy
    )

    val isValid = schnorrSignatureScheme.verifySignature(
        dataToSign,
        schnorrSignatureScheme.decodePublicKey(finalSignature.getSigningPublicKey()),
        schnorrSignatureScheme.decodePublicKey(finalSignature.getRandomPublicKey()),
        BigInteger(finalSignature.getSigma())
    )
    println("Combined Schnorr Signature: ${BigInteger(finalSignature.getSigma()).toString(16)}")
    println("The Schnorr signature is ${if (isValid) "valid" else "invalid"}.\n")

    // Sign a message (BLS signature)
    val message = "BLSSignatureTest".toByteArray()
    val blsSignatureResponse = signData(blsPrivateKeyId, message, SignatureScheme.BLS, serviceProxy)

    val blsSignature = BlsSignature.buildFinalSignature(
        blsSignatureResponse,
        blsSignatureScheme,
        message,
    )
    println("Combined BLS Signature: ${BigInteger(blsSignature.getSignature()).toString(16)}")
    println("Combined BLS Public Key: ${BigInteger(blsSignature.getSigningPublicKey()).toString(16)}")

    val isValidBlsSignature = blsSignatureScheme.verifySignature(blsSignature.getSignature(), message, blsSignature.getSigningPublicKey())
    println("The BLS signature is ${if (isValidBlsSignature) "valid" else "invalid"}.\n")

    val shareholders = (0..<serviceProxy.currentN).map { it.toBigInteger() }.toTypedArray()
    repeat(1) {

        val messageToEncrypt = "This is data to be encrypted"
        println("Encryption of the message: \"$messageToEncrypt\"\n")
        val committedData = dise.commitData(messageToEncrypt.toByteArray())

        val encryptionResponse = encryptDecryptData(committedData.serialize(), Operation.ENCRYPT, serviceProxy)

        val encPartialResults = encryptionResponse.getVerifiableShares()[0].associate {
            it.share.shareholder to DPRFResult.deserialize(it.share.share.toByteArray())
        }

        val encContributions = encPartialResults.map { it.value.contribution }.toTypedArray()
        val commitmentsMap = encPartialResults.map { it.key to it.value.publicParameters.getSecretKeyShareCommitmentOf(it.key) }.toMap()
        val firstPublicParameters = encPartialResults.values.first().publicParameters
        val dprfPublicParameters = DPRFPublicParameters(
            firstPublicParameters.getGenerator(),
            firstPublicParameters.getGeneratorCommitment(),
            commitmentsMap,
        )
//    println(encPartialResults.forEach { println("${it.key}: ${it.value.contribution}\n${it.value.publicParameters}") })
//        println(encPartialResults.keys.toString())
//    encContributions.forEach { println(it) }

        // Maybe place the encEvalInput inside encrypt function
        val encEvalInput = BigInteger(1, "$clientId".toByteArray().plus(committedData.alpha))
        val ciphertext = dise.encrypt(
            messageToEncrypt.toByteArray(),
            committedData,
            encEvalInput,
            dprfPublicParameters,
            encPartialResults.keys.toTypedArray(),
            encContributions,
        )
        if (ciphertext == null) {
            println("Encryption not successful")
            return
        }
//        println(DiSECiphertext.deserialize(ciphertext))

        val parsedCiphertext = dise.parseEncryptedData(ciphertext)
        val ciphertextMetadata = parsedCiphertext.toCiphertextMetadata()
        val decEvalInput = BigInteger(1, "${parsedCiphertext.encryptorId}".toByteArray().plus(parsedCiphertext.alpha))

        val decryptionResponse = encryptDecryptData(ciphertextMetadata.serialize(), Operation.DECRYPT, serviceProxy)
//    val decContributions = decryptionResponse.getVerifiableShares()[0].map { DPRFContribution.deserialize(it.share.share.toByteArray()) }.toTypedArray()

        val decPartialResults = decryptionResponse.getVerifiableShares()[0].associate {
            it.share.shareholder to DPRFResult.deserialize(it.share.share.toByteArray())
        }
        val decContributions = decPartialResults.map { it.value.contribution }.toTypedArray()
        val decCommitmentsMap =
            decPartialResults.map { it.key to it.value.publicParameters.getSecretKeyShareCommitmentOf(it.key) }.toMap()
        val decFirstPublicParameters = decPartialResults.values.first().publicParameters
        val decDprfPublicParameters = DPRFPublicParameters(
            decFirstPublicParameters.getGenerator(),
            decFirstPublicParameters.getGeneratorCommitment(),
            decCommitmentsMap,
        )
//        println(decPartialResults.keys.toString())
//    decContributions.forEach { println(it) }

        val decryptedMessage = dise.decrypt(
            parsedCiphertext,
            decEvalInput,
            decDprfPublicParameters,
            decPartialResults.keys.toTypedArray(),
            decContributions,
        )
        println("\n$it: Decrypted message: \"${decryptedMessage?.decodeToString()}\"")
    }
}

fun testSchnorrKeyPairGenLatency(times: Int, serviceProxy: ConfidentialServiceProxy) {
    println("* testSchnorrKeyPairGenLatency: STARTING")
    val executionTimes = DoubleArray(times)
    repeat(times) {
        val millis = measureTimeMillis {
            val schnorrPrivateKeyId = "schnorr$it"
            val schnorrSigningKeyResponse = generateSigningKey(schnorrPrivateKeyId, SignatureScheme.SCHNORR, serviceProxy)
//            val schnorrPublicKey = schnorrSigningKeyResponse.getPlainData()
//            println(BigInteger(schnorrPublicKey).toString(16))
        }
        executionTimes[it] = millis.toDouble()
        println("$it:\t${millis / 1000.0}")
    }
    println("* testSchnorrKeyPairGenLatency: DONE\n")
    printStats(executionTimes)
}

fun testBLSKeyPairGenLatency(times: Int, serviceProxy: ConfidentialServiceProxy) {
    println("* testBLSKeyPairGenLatency: STARTING")
    val executionTimes = DoubleArray(times)
    repeat(times) {
        val millis = measureTimeMillis {
            val blsPrivateKeyId = "bls$it"
            val blsSigningKeyResponse = generateSigningKey(blsPrivateKeyId, SignatureScheme.BLS, serviceProxy)
//            val blsPublicKey = BlsSignature.buildFinalPublicKey(blsSigningKeyResponse, blsSignatureScheme)
//            println(BigInteger(blsPublicKey).toString(16))
        }
        executionTimes[it] = millis.toDouble()
        println("$it:\t${millis / 1000.0}")
    }
    println("* testBLSKeyPairGenLatency: DONE\n")
    printStats(executionTimes)
}

fun testSchnorrSignatureLatency(times: Int, schnorrSignatureScheme: SchnorrSignatureScheme, serviceProxy: ConfidentialServiceProxy) {
    // Generates a Schnorr signing key (private key & public key)
    val schnorrPrivateKeyId = "schnorrsigntest"
    val schnorrSigningKeyResponse = generateSigningKey(schnorrPrivateKeyId, SignatureScheme.SCHNORR, serviceProxy)
    val schnorrPublicKey = schnorrSigningKeyResponse.getPlainData()
    println("Schnorr signing public key: ${BigInteger(schnorrPublicKey).toString(16)}\n")

    println("* testSchnorrSignatureLatency: STARTING")
    val executionTimes = DoubleArray(times)
    repeat(times) {
        val millis = measureTimeMillis {
            val dataToSign = "HSM".toByteArray()
            val signatureResponse = signData(schnorrPrivateKeyId, dataToSign, SignatureScheme.SCHNORR, serviceProxy)

            val finalSignature = SchnorrSignature.buildFinalSignature(
                signatureResponse,
                schnorrSignatureScheme,
                dataToSign,
                serviceProxy
            )
        }
        executionTimes[it] = millis.toDouble()
        println("$it:\t${millis / 1000.0}")
    }
    println("* testSchnorrSignatureLatency: DONE\n")
    printStats(executionTimes)
}

fun testBLSSignatureLatency(times: Int, blsSignatureScheme: BlsSignatureScheme, serviceProxy: ConfidentialServiceProxy) {
    // Generates a BLS signing key (private key & public key)
    val blsPrivateKeyId = "blssigntest"
    val blsSigningKeyResponse = generateSigningKey(blsPrivateKeyId, SignatureScheme.BLS, serviceProxy)
    val blsPublicKey = BlsSignature.buildFinalPublicKey(blsSigningKeyResponse, blsSignatureScheme)
    println("BLS signing public key: ${BigInteger(blsPublicKey).toString(16)}\n")

    println("* testBLSSignatureLatency: STARTING")
    val executionTimes = DoubleArray(times)
    repeat(times) {
        val millis = measureTimeMillis {
            // Sign a message (BLS signature)
            val message = "BLSSignatureTest".toByteArray()
            val blsSignatureResponse = signData(blsPrivateKeyId, message, SignatureScheme.BLS, serviceProxy)

            val blsSignature = BlsSignature.buildFinalSignature(
                blsSignatureResponse,
                blsSignatureScheme,
                message,
            )
        }
        executionTimes[it] = millis.toDouble()
        println("$it:\t${millis / 1000.0}")
    }
    println("* testBLSSignatureLatency: DONE\n")
    printStats(executionTimes)
}

fun testEncryptionLatency(times: Int, clientId: BigInteger, dise: DiSE, serviceProxy: ConfidentialServiceProxy) {
    println("* testEncryptionLatency: STARTING")
    val executionTimes = DoubleArray(times)
    repeat(times) {
        val millis = measureTimeMillis {
            val messageToEncrypt = "This is data to be encrypted"
//            println("Encryption of the message: \"$messageToEncrypt\"\n")
            val committedData = dise.commitData(messageToEncrypt.toByteArray())

            val encryptionResponse = encryptDecryptData(committedData.serialize(), Operation.ENCRYPT, serviceProxy)

            val encPartialResults = encryptionResponse.getVerifiableShares()[0].associate {
                it.share.shareholder to DPRFResult.deserialize(it.share.share.toByteArray())
            }

            val encContributions = encPartialResults.map { it.value.contribution }.toTypedArray()
            val commitmentsMap = encPartialResults.map { it.key to it.value.publicParameters.getSecretKeyShareCommitmentOf(it.key) }.toMap()
            val firstPublicParameters = encPartialResults.values.first().publicParameters
            val dprfPublicParameters = DPRFPublicParameters(
                firstPublicParameters.getGenerator(),
                firstPublicParameters.getGeneratorCommitment(),
                commitmentsMap,
            )
//            println(encPartialResults.forEach { println("${it.key}: ${it.value.contribution}\n${it.value.publicParameters}") })
//            println(encPartialResults.keys.toString())
            //        encContributions.forEach { println(it) }

            // Maybe place the encEvalInput inside encrypt function
            val encEvalInput = BigInteger(1, "$clientId".toByteArray().plus(committedData.alpha))
            val ciphertext = dise.encrypt(
                messageToEncrypt.toByteArray(),
                committedData,
                encEvalInput,
                dprfPublicParameters,
                encPartialResults.keys.toTypedArray(),
                encContributions,
            )
            if (ciphertext == null) {
                println("Encryption not successful")
                return
            }
//            println(DiSECiphertext.deserialize(ciphertext))

            val parsedCiphertext = dise.parseEncryptedData(ciphertext)
            val ciphertextMetadata = parsedCiphertext.toCiphertextMetadata()
            val decEvalInput = BigInteger(1, "${parsedCiphertext.encryptorId}".toByteArray().plus(parsedCiphertext.alpha))

            val decryptionResponse = encryptDecryptData(ciphertextMetadata.serialize(), Operation.DECRYPT, serviceProxy)

            val decPartialResults = decryptionResponse.getVerifiableShares()[0].associate {
                it.share.shareholder to DPRFResult.deserialize(it.share.share.toByteArray())
            }
            val decContributions = decPartialResults.map { it.value.contribution }.toTypedArray()
            val decCommitmentsMap =
                decPartialResults.map { it.key to it.value.publicParameters.getSecretKeyShareCommitmentOf(it.key) }.toMap()
            val decFirstPublicParameters = decPartialResults.values.first().publicParameters
            val decDprfPublicParameters = DPRFPublicParameters(
                decFirstPublicParameters.getGenerator(),
                decFirstPublicParameters.getGeneratorCommitment(),
                decCommitmentsMap,
            )
//            println(decPartialResults.keys.toString())
//    decContributions.forEach { println(it) }

            val decryptedMessage = dise.decrypt(
                parsedCiphertext,
                decEvalInput,
                decDprfPublicParameters,
                decPartialResults.keys.toTypedArray(),
                decContributions,
            )
//            println("\n$it: Decrypted message: \"${decryptedMessage?.decodeToString()}\"")
        }
        executionTimes[it] = millis.toDouble()
        println("$it:\t${millis / 1000.0}")
    }
    println("* testEncryptionLatency: DONE\n")
    printStats(executionTimes)
}

private fun printStats(executionTimes: DoubleArray) {
    val results = executionTimes.drop((executionTimes.size * 0.1).toInt()).toDoubleArray()

    println("+ Mean: ${results.average()} ms")
    println("+ Standard Deviation: ${standardDeviation(results)}")
}
private fun standardDeviation(numbers: DoubleArray): Double {
    val mean = numbers.average()
    val variance = numbers.map { (it - mean).pow(2) }.average()
    return sqrt(variance)
}
