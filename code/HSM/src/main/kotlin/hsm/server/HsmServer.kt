package hsm.server

import bftsmart.communication.ServerCommunicationSystem
import bftsmart.tom.MessageContext
import bftsmart.tom.ServiceReplica
import bls.BLS
import confidential.ConfidentialMessage
import confidential.EllipticCurveConstants
import confidential.facade.server.ConfidentialSingleExecutable
import confidential.polynomial.DistributedPolynomialManager
import confidential.polynomial.RandomKeyPolynomialListener
import confidential.polynomial.RandomPolynomialContext
import confidential.polynomial.RandomPolynomialListener
import confidential.server.ConfidentialRecoverable
import confidential.server.ServerConfidentialityScheme
import confidential.statemanagement.ConfidentialSnapshot
import hsm.Operation
import hsm.Operation.GENERATE_SIGNING_KEY
import hsm.Operation.SIGN_DATA
import hsm.communications.KeyGenerationRequest
import hsm.communications.SignatureRequest
import hsm.database.HsmDatabase
import hsm.database.SimpleDatabase
import hsm.signatures.SchnorrPublicPartialSignature
import hsm.signatures.SchnorrSignatureScheme
import hsm.signatures.SignatureScheme
import hsm.signatures.bls.BlsSignature
import org.bouncycastle.math.ec.ECPoint
import org.slf4j.LoggerFactory
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import vss.commitment.linear.LinearCommitments
import vss.secretsharing.Share
import vss.secretsharing.VerifiableShare
import java.io.*
import java.math.BigInteger
import java.security.MessageDigest
import java.util.*
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.system.exitProcess

private typealias PolynomialId = Int
private typealias ClientId = Int
private data class RequestOperation(val clientId: Int, val operation: Operation)
private data class KeyGenerationData(val keyGenerationRequest: KeyGenerationRequest, val messageContext: MessageContext)
private data class SignatureRequestDto(val privateKeyId: String, val dataToSign: ByteArray, val signatureScheme: SignatureScheme, val messageContext: MessageContext)

class HsmServer(private val id: Int): ConfidentialSingleExecutable, RandomPolynomialListener, RandomKeyPolynomialListener {
    private val logger = LoggerFactory.getLogger("hsm")
    private val serverCommunicationSystem: ServerCommunicationSystem
    private val distributedPolynomialManager: DistributedPolynomialManager
    private val serviceReplica: ServiceReplica
    private val cr: ConfidentialRecoverable
    private val messageDigest: MessageDigest

    // Used during requests and data map accesses
    private val lock: Lock

    // Stores requests to get random number
    private var requests: MutableMap<PolynomialId, MessageContext>

    // Stores clients' random number shares of clients
    private var data: MutableMap<ClientId, VerifiableShare>         // <client id, random number's share>

    // Stores data for signing
    private val signingData: Map<ClientId, ByteArray>               // <client id, data for signing>

    // Stores the private key shares of each client
    data class SignatureKeyPair(val privateKeyShare: VerifiableShare, val publicKey: ByteArray, val signatureScheme: SignatureScheme)
    private val database: HsmDatabase<String, SignatureKeyPair>      // <client id + key id, signature key pair>

    // Stores requests for generating a random key and associates the polynomial id with the corresponding operation
    private val randomKeyGenerationRequests: MutableMap<PolynomialId, RequestOperation>

    // Stores requests for generating a signing key
    private val signKeyGenerationRequests: MutableMap<ClientId, KeyGenerationData>

    // Stores requests for issuing a signature
    private val signatureRequests: MutableMap<ClientId, SignatureRequestDto>

    private val schnorrSignatureScheme: SchnorrSignatureScheme
    private val blsSignatureScheme: BLS

    init {
        lock = ReentrantLock(true)
        messageDigest = MessageDigest.getInstance("SHA256")
        requests = TreeMap()
        data = TreeMap()
        signingData = TreeMap()
        cr = ConfidentialRecoverable(id, this)
        serviceReplica = ServiceReplica(id, cr, cr, cr)
        serverCommunicationSystem = serviceReplica.serverCommunicationSystem
        distributedPolynomialManager = cr.distributedPolynomialManager
        distributedPolynomialManager.setRandomPolynomialListener(this)
        distributedPolynomialManager.setRandomKeyPolynomialListener(this)

        database = SimpleDatabase()

        randomKeyGenerationRequests = TreeMap()
        signKeyGenerationRequests = TreeMap()
        signatureRequests = TreeMap()

        val confidentialitySchemes = HashMap<String, ServerConfidentialityScheme>()
        confidentialitySchemes[EllipticCurveConstants.BLS12_381.NAME] =
            ServerConfidentialityScheme(
                id,
                serviceReplica.replicaContext.currentView,
                EllipticCurveConstants.BLS12_381.PARAMETERS
            )
        confidentialitySchemes[EllipticCurveConstants.secp256r1.NAME] =
            ServerConfidentialityScheme(
                id,
                serviceReplica.replicaContext.currentView,
                EllipticCurveConstants.secp256r1.PARAMETERS
            )
        confidentialitySchemes[EllipticCurveConstants.secp256k1.NAME] =
            ServerConfidentialityScheme(
                id,
                serviceReplica.replicaContext.currentView,
                EllipticCurveConstants.secp256k1.PARAMETERS
            )
        cr.registerConfidentialitySchemes(confidentialitySchemes)

        schnorrSignatureScheme = SchnorrSignatureScheme()
        blsSignatureScheme = BLS(serviceReplica.replicaContext.currentView.f)
    }

    override fun appExecuteOrdered(
        bytes: ByteArray,
        verifiableShares: Array<VerifiableShare?>?,
        messageContext: MessageContext
    ): ConfidentialMessage? {
        val messageSenderId = messageContext.sender
        val op = Operation.getOperation(bytes[0].toInt())
        val receivedData = bytes.copyOfRange(1, bytes.size)
        logger.info("Received a {} request from {} in cid {}", op, messageSenderId, messageContext.consensusId)
        when (op) {
            GENERATE_SIGNING_KEY -> {
                lock.withLock {
                    val keyGenRequest = KeyGenerationRequest.deserialize(receivedData)
                    val indexKey = buildDatabaseIndexKey(keyGenRequest.privateKeyId, messageSenderId)

                    if (database.containsKey(indexKey)) {
                        logger.warn("Already exists a signing key associated with index key.")
                        sendPublicKeyTo(messageContext, database.get(indexKey)!!)
                    } else if (signKeyGenerationRequests.isEmpty()) {
                        val polynomialId = generateSigningKey(
                            when (keyGenRequest.signatureScheme) {
                                SignatureScheme.SCHNORR -> EllipticCurveConstants.secp256k1.NAME
                                SignatureScheme.BLS -> EllipticCurveConstants.BLS12_381.NAME
                            }
                        )
                        randomKeyGenerationRequests[polynomialId] = RequestOperation(messageSenderId, GENERATE_SIGNING_KEY)

                        val messageData = KeyGenerationData(keyGenRequest, messageContext)
                        signKeyGenerationRequests[messageSenderId] = messageData
                        logger.info("Generating signing key with polynomial id {}", polynomialId)
                    } else {
                        logger.warn("Signing key is already being created.")
                    }
                }
            }
            SIGN_DATA -> {
                lock.withLock {
                    val signatureRequestDto = SignatureRequest.deserialize(receivedData).toDto(messageContext)
                    signatureRequests[messageSenderId] = signatureRequestDto

                    when (signatureRequestDto.signatureScheme) {
                        SignatureScheme.SCHNORR -> {
                            // In case of Schnorr signature we need to generate a new random key-pair
                            val polynomialId = generateSigningKey(EllipticCurveConstants.secp256k1.NAME)
                            randomKeyGenerationRequests[polynomialId] = RequestOperation(messageSenderId, SIGN_DATA)
                        }
                        SignatureScheme.BLS -> {
                            signBlsAndSend(messageSenderId)
                        }
                    }
                }
            }
            else -> return null
        }
        return null
    }

    /**
     * Generates a signing key through the COBRA's distributed polynomial protocol.
     * @param confidentialitySchemeId identifier of the confidentiality scheme to select the correct elliptic curve.
     * @return the identifier of the distributed polynomial that will be created.
     */
    private fun generateSigningKey(confidentialitySchemeId: String): Int {
        return distributedPolynomialManager.createRandomKeyPolynomial(
            serviceReplica.replicaContext.currentView.f,
            serviceReplica.replicaContext.currentView.processes,
            confidentialitySchemeId
        )
    }

    /**
     * Method called by the polynomial generation manager when the requested random key is generated
     * @param context Random number share and its context
     */
    override fun onRandomKeyPolynomialsCreation(context: RandomPolynomialContext) {
        lock.lock()
        val privateKeyShare = context.point
        val commitment = (context.point.commitments as EllipticCurveCommitment).commitment
        val publicKey = commitment[commitment.size - 1]
        onRandomKey(context.initialId, privateKeyShare, publicKey)
        lock.unlock()
    }

    /**
     * Stores the generated private key share in the database and sends the corresponding public key to the respective
     * client.
     */
    private fun onRandomKey(polynomialId: Int, privateKeyShare: VerifiableShare, publicKey: ECPoint) {
        if (!randomKeyGenerationRequests.containsKey(polynomialId)) {
            logger.warn("Received an unknown polynomial id {}", polynomialId)
            // TODO: Send some value correspondent to the error specified in PKCS#11
            return
        }
        logger.info("Received key share of the random signing key generated from the polynomial id {}", polynomialId)

        val (clientId, operation) = randomKeyGenerationRequests.remove(polynomialId)!!
        when (operation) {
            GENERATE_SIGNING_KEY -> {
                val (keyGenRequest, messageContext) = signKeyGenerationRequests.remove(clientId)!!
                val databaseIndexKey = buildDatabaseIndexKey(keyGenRequest.privateKeyId, messageContext.sender)

                val publicKeyEncoded = when (keyGenRequest.signatureScheme) {
                    SignatureScheme.SCHNORR -> publicKey.getEncoded(true)
                    SignatureScheme.BLS -> blsSignatureScheme.computePublicKey(privateKeyShare.share.share)
                }
                val signatureKeyPair = SignatureKeyPair(privateKeyShare, publicKeyEncoded, keyGenRequest.signatureScheme)

                val result = database.add(databaseIndexKey, signatureKeyPair) ?: return // TODO: Send PKCS#11 error value.
                sendPublicKeyTo(messageContext, signatureKeyPair)
            }
            SIGN_DATA -> {
                val (privateKeyId, dataToSign, signatureScheme, messageContext) = signatureRequests.remove(clientId)!!
                if (signatureScheme != SignatureScheme.SCHNORR) return // TODO: Send appropriate error
                val chosenSignatureKeypair = getSignatureKeyPair(privateKeyId, messageContext.sender) ?: return // TODO: Send PKCS#11 error value.

                logger.info("Computing partial Schnorr signature for client {}", clientId)
                val randomPrivateKeyShare = privateKeyShare
                val randomPublicKey = publicKey
                signSchnorrAndSend(messageContext, dataToSign, chosenSignatureKeypair, randomPrivateKeyShare, randomPublicKey)
            }
            else -> return
        }
        // TODO: Send some value correspondent to the success or error specified in PKCS#11 for the response.
    }

    /**
     * Issues a BLS signature for the provided data, more specifically a partial signature, and then sends it to the
     * corresponding client.
     */
    private fun signBlsAndSend(clientId: Int) {
        val (privateKeyId, dataToSign, _, receiverContext) = signatureRequests.remove(clientId)!!
        val chosenSigningKeyPair = getSignatureKeyPair(privateKeyId, receiverContext.sender) ?: return // TODO: Send PKCS#11 error value.
        logger.info("Computing partial BLS signature for client {}", clientId)

        val privateKeyShare = chosenSigningKeyPair.privateKeyShare.share.share

        val partialSignatureBytes = blsSignatureScheme.sign(privateKeyShare.toByteArray(), dataToSign)

        val partialSignature = BlsSignature(partialSignatureBytes, chosenSigningKeyPair.publicKey)

        val partialSignatureWithPubKey = VerifiableShare(
            Share(cr.shareholderId, BigInteger(partialSignature.serialize())),
            LinearCommitments(BigInteger.ZERO),
            null
        )

        val response = ConfidentialMessage(ByteArray(0), partialSignatureWithPubKey)
        sendResponseTo(receiverContext, response)
        logger.info("Sent partial BLS signature for client {}", receiverContext.sender)
    }

    /**
     * Builds the index key associated to a private key share. The index key is composed by the sender id / client id
     * concatenated with the identifier sent by the client to be associated with the generated private key share.
     * @return the index key associated with a private key share.
     */
    private fun buildDatabaseIndexKey(keyIdentifier: String, messageSenderId: Int): String {
        return "$messageSenderId$keyIdentifier"
    }

    /**
     * Obtains the public key associated with the provided private key share.
     * @param privateKeyShare private key share of the desired public key.
     * @return the corresponding public key.
     */
    private fun getPublicKey(privateKeyShare: VerifiableShare): ECPoint {
        val commitment = (privateKeyShare.commitments as EllipticCurveCommitment).commitment
        return commitment[commitment.size - 1]
    }

    /**
     * Sends a public key as the response message to a specific client.
     * @param receiverContext Information about the requesting client.
     * @param signatureKeyPair Public key and its respective signature scheme to send to the client.
     */
    private fun sendPublicKeyTo(receiverContext: MessageContext, signatureKeyPair: SignatureKeyPair) {
        val response = when (signatureKeyPair.signatureScheme) {
            SignatureScheme.SCHNORR -> ConfidentialMessage(signatureKeyPair.publicKey)
            SignatureScheme.BLS -> ConfidentialMessage(
                ByteArray(0),
                VerifiableShare(
                    Share(cr.shareholderId, BigInteger(signatureKeyPair.publicKey)),
                    LinearCommitments(BigInteger.ZERO),
                    null
            )   )
        }
        sendResponseTo(receiverContext, response)
    }

    /**
     * Sends a response to a specific client.
     * @param receiverContext Information about the requesting client.
     * @param response The response to send back to the client.
     */
    private fun sendResponseTo(receiverContext: MessageContext, response: ConfidentialMessage) {
        cr.sendMessageToClient(receiverContext, response)
    }

    /**
     * Method called by the polynomial generation manager when the requested random number is generated
     * @param context Random number share and its context
     */
    override fun onRandomPolynomialsCreation(context: RandomPolynomialContext) {
        lock.lock()
        val delta = context.time / 1000000.0
        logger.debug("Received random number polynomial with id {} in {} ms", context.initialId, delta)
        val messageContext: MessageContext = requests.remove(context.initialId)!!
        data[messageContext.sender] = context.point
        logger.debug("Sending random number share to {}", messageContext.sender)
        sendRandomNumberShareTo(messageContext, context.point)
        lock.unlock()
    }

    /**
     * Method used to asynchronously send the random number share
     * @param receiverContext Information about the requesting client
     * @param share Random number share
     */
    private fun sendRandomNumberShareTo(receiverContext: MessageContext, share: VerifiableShare?) {
        val response = ConfidentialMessage(null, share)
        sendResponseTo(receiverContext, response)
    }

    private fun signSchnorrAndSend(
        receiverContext: MessageContext,
        data: ByteArray,
        chosenSigningKeyPair: SignatureKeyPair,
        randomPrivateKeyShare: VerifiableShare,
        randomPublicKey: ECPoint
    ) {
        val signingPrivateKeyShare: VerifiableShare = chosenSigningKeyPair.privateKeyShare
        val sigma = schnorrSignatureScheme.computePartialSignature(
            data,
            signingPrivateKeyShare.share.share,
            randomPrivateKeyShare.share.share,
            randomPublicKey
        ).add(if (serviceReplica.id == 0) BigInteger.ONE else BigInteger.ZERO)

        val publicPartialSignature = SchnorrPublicPartialSignature(
            signingPrivateKeyShare.commitments as EllipticCurveCommitment,
            randomPrivateKeyShare.commitments as EllipticCurveCommitment,
            randomPublicKey,
            chosenSigningKeyPair.publicKey
        )

        lateinit var plainData: ByteArray
        try {
            ByteArrayOutputStream().use { bos ->
                ObjectOutputStream(bos).use { out ->
                    publicPartialSignature.serialize(out)
                    out.flush()
                    bos.flush()
                    plainData = bos.toByteArray()
                }
            }
        } catch (e: IOException) {
            e.printStackTrace()
        }

        val partialSignature = VerifiableShare(
            Share(cr.shareholderId, sigma),
            LinearCommitments(BigInteger.ZERO),
            null
        )

        val response = ConfidentialMessage(plainData, partialSignature)
        sendResponseTo(receiverContext, response)
        logger.info("Sent partial Schnorr signature for client {}", receiverContext.sender)
    }

    /**
     * Obtains the private key share from the database if exists.
     * @return the private key share or null when it does not exist.
     */
    private fun getSignatureKeyPair(
        privateKeyId: String,
        messageSenderId: Int
    ) = database.get(buildDatabaseIndexKey(privateKeyId, messageSenderId))


    override fun appExecuteUnordered(
        bytes: ByteArray?,
        verifiableShares: Array<VerifiableShare?>?,
        messageContext: MessageContext?
    ): ConfidentialMessage? {
        return null
    }

    override fun getConfidentialSnapshot(): ConfidentialSnapshot? {
        try {
            ByteArrayOutputStream().use { bout ->
                ObjectOutputStream(bout).use { out ->
                    out.writeInt(requests.size)
                    for ((key, value) in requests) {
                        out.writeInt(key)
                        out.writeObject(value)
                    }
                    out.writeInt(data.size)
                    val shares = arrayOfNulls<VerifiableShare>(data.size)
                    for ((index, entry: Map.Entry<Int, VerifiableShare>) in data.entries.withIndex()) {
                        out.writeInt((entry.key))
                        entry.value.writeExternal(out)
                        shares[index] = entry.value
                    }
                    out.flush()
                    bout.flush()
                    return ConfidentialSnapshot(bout.toByteArray(), *shares)
                }
            }
        } catch (e: IOException) {
            logger.error("Error while taking snapshot", e)
        }
        return null
    }

    override fun installConfidentialSnapshot(confidentialSnapshot: ConfidentialSnapshot) {
        try  {
            ByteArrayInputStream(confidentialSnapshot.plainData).use { bin ->
                ObjectInputStream(bin).use { `in` ->
                    var size = `in`.readInt()
                    requests = TreeMap<Int, MessageContext>()
                    while (size-- > 0) {
                        val key: Int = `in`.readInt()
                        val value: MessageContext = `in`.readObject() as MessageContext
                        requests[key] = value
                    }
                    size = `in`.readInt()
                    data = TreeMap<Int, VerifiableShare>()
                    val shares: Array<VerifiableShare> = confidentialSnapshot.shares
                    for (i in 0..<size) {
                        val key: Int = `in`.readInt()
                        val value: VerifiableShare = shares[i]
                        value.readExternal(`in`)
                        data[key] = value
                    }
                }
            }
        } catch (e: Exception) {
            when (e) {
                is IOException,
                is ClassCastException,
                is ClassNotFoundException -> logger.error("Error while installing snapshot", e)
            }
        }
    }
}

private fun SignatureRequest.toDto(messageContext: MessageContext): SignatureRequestDto = SignatureRequestDto(
    privateKeyId, dataToSign, signatureScheme, messageContext
)



fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: hsm.server.HsmServerKt <server id>")
        exitProcess(-1)
    }
    HsmServer(args[0].toInt())
}