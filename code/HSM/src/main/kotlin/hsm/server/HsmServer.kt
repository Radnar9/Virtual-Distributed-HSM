package hsm.server

import bftsmart.communication.ServerCommunicationSystem
import bftsmart.tom.MessageContext
import bftsmart.tom.ServiceReplica
import bftsmart.tom.core.messages.TOMMessage
import confidential.ConfidentialMessage
import confidential.facade.server.ConfidentialSingleExecutable
import confidential.polynomial.DistributedPolynomialManager
import confidential.polynomial.RandomKeyPolynomialListener
import confidential.polynomial.RandomPolynomialContext
import confidential.polynomial.RandomPolynomialListener
import confidential.server.ConfidentialRecoverable
import confidential.statemanagement.ConfidentialSnapshot
import hsm.Operation
import hsm.Operation.GENERATE_SIGNING_KEY
import hsm.Operation.SIGN_DATA
import hsm.communications.SignatureRequest
import hsm.database.HsmDatabase
import hsm.database.SimpleDatabase
import hsm.signatures.PublicPartialSignature
import hsm.signatures.SchnorrSignatureScheme
import hsm.signatures.SignatureScheme
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
private data class RequestData(val sentData: ByteArray, val messageContext: MessageContext)
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
    private val database: HsmDatabase<String, VerifiableShare>      // <client id + key id, private key share>
    // TODO: Maybe I'll need to have a way of differentiating between an asymmetric and symmetric key and to verify if it's compliant with the desired scheme (Schnorr/BLS..).
    // TODO: Should I store the public key as well? Storage size vs performance.

    // Stores requests for generating a random key and associates the polynomial id with the corresponding operation
    private val randomKeyGenerationRequests: MutableMap<PolynomialId, RequestOperation>

    // Stores requests for generating a signing key
    private val signKeyGenerationRequests: MutableMap<ClientId, RequestData>

    // Stores requests for issuing a signature
    private val signatureRequests: MutableMap<ClientId, SignatureRequestDto>

    private val schnorrSignatureScheme: SchnorrSignatureScheme

    init {
        lock = ReentrantLock(true)
        messageDigest = MessageDigest.getInstance("SHA256")
        requests = TreeMap()
        data = TreeMap()
        signingData = TreeMap()
        cr = ConfidentialRecoverable(id, this)
        serviceReplica = ServiceReplica(id, cr, cr, null, null, null, null, cr)
        serverCommunicationSystem = serviceReplica.serverCommunicationSystem
        distributedPolynomialManager = cr.distributedPolynomialManager
        distributedPolynomialManager.setRandomPolynomialListener(this)
        distributedPolynomialManager.setRandomKeyPolynomialListener(this)

        database = SimpleDatabase()

        randomKeyGenerationRequests = TreeMap()
        signKeyGenerationRequests = TreeMap()
        signatureRequests = TreeMap()

        schnorrSignatureScheme = SchnorrSignatureScheme()
    }

    override fun appExecuteOrdered(
        bytes: ByteArray,
        verifiableShares: Array<VerifiableShare?>?,
        messageContext: MessageContext
    ): ConfidentialMessage? {
        val op = Operation.getOperation(bytes[0].toInt())
        logger.info("Received a {} request from {} in cid {}", op, messageContext.sender, messageContext.consensusId)
        val sentData = bytes.copyOfRange(1, bytes.size)
        when (op) {
            GENERATE_SIGNING_KEY -> {
                lock.withLock {
                    val keyIdentifier = sentData.decodeToString()
                    val indexKey = buildDatabaseIndexKey(keyIdentifier, messageContext)

                    if (database.containsKey(indexKey)) {
                        logger.warn("Already exists a signing key associated with index key.")
                        sendPublicKeyTo(messageContext, getPublicKey(database.get(indexKey)!!))
                    } else if (signKeyGenerationRequests.isEmpty()) {
                        val polynomialId = generateSigningKey()
                        randomKeyGenerationRequests[polynomialId] = RequestOperation(messageContext.sender, GENERATE_SIGNING_KEY)

                        val messageData = RequestData(sentData, messageContext)
                        signKeyGenerationRequests[messageContext.sender] = messageData
                        logger.info("Generating signing key with polynomial id {}", polynomialId)
                    } else {
                        logger.warn("Signing key is already being created.")
                    }
                }
            }
            SIGN_DATA -> {
                lock.withLock {
                    val signatureRequestDto = SignatureRequest.deserialize(sentData).toDto(messageContext)
                    signatureRequests[messageContext.sender] = signatureRequestDto

                    // In case of Schnorr signature we need to generate a new random key-pair
                    val polynomialId = generateSigningKey()
                    randomKeyGenerationRequests[polynomialId] = RequestOperation(messageContext.sender, SIGN_DATA)
                }
            }
            else -> return null
        }
        return null
    }

    /**
     * Generates a signing key through the COBRA's distributed polynomial protocol.
     * @return the identifier of the distributed polynomial that will be created.
     */
    private fun generateSigningKey(): Int {
        return distributedPolynomialManager.createRandomKeyPolynomial(
            serviceReplica.replicaContext.currentView.f,
            serviceReplica.replicaContext.currentView.processes
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
        onRandomKey(context.id, privateKeyShare, publicKey)
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
                val (keyIdentifier, messageContext) = signKeyGenerationRequests.remove(clientId)!!
                val databaseIndexKey = buildDatabaseIndexKey(keyIdentifier.decodeToString(), messageContext)
                val result = database.add(databaseIndexKey, privateKeyShare) ?: return // TODO: Send PKCS#11 error value.
                sendPublicKeyTo(messageContext, publicKey)
            }
            SIGN_DATA -> {
                val (privateKeyId, dataToSign, signatureScheme, messageContext) = signatureRequests.remove(clientId)!!
                val chosenPrivateKeyShare = database.get(buildDatabaseIndexKey(privateKeyId, messageContext)) ?: return // TODO: Send PKCS#11 error value.
                val randomPrivateKeyShare = privateKeyShare
                val randomPublicKey = publicKey
                logger.info("Computing partial signature for client {}", clientId)
                signAndSend(messageContext, dataToSign, chosenPrivateKeyShare, randomPrivateKeyShare, randomPublicKey)
            }
            else -> return
        }
        // TODO: Send some value correspondent to the success or error specified in PKCS#11 for the response.
    }

    /**
     * Builds the index key associated to a private key share. The index key is composed by the sender id / client id
     * concatenated with the identifier sent by the client to be associated with the generated private key share.
     * @return the index key associated with a private key share.
     */
    private fun buildDatabaseIndexKey(keyIdentifier: String, messageContext: MessageContext): String {
        return "${messageContext.sender}$keyIdentifier"
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
     * @param publicKey Public key to send to the client.
     */
    private fun sendPublicKeyTo(receiverContext: MessageContext, publicKey: ECPoint) {
        val encodedPublicKey = publicKey.getEncoded(true)
        val response = ConfidentialMessage(encodedPublicKey)
        sendResponseTo(receiverContext, response)
    }

    /**
     * Sends a response to a specific client.
     * @param receiverContext Information about the requesting client.
     * @param response The response to send back to the client.
     */
    private fun sendResponseTo(receiverContext: MessageContext, response: ConfidentialMessage) {
        val tomMessage = TOMMessage(
            id,
            receiverContext.session,
            receiverContext.sequence,
            receiverContext.operationId,
            response.serialize(),
            serviceReplica.replicaContext.svController.currentViewId,
            receiverContext.type
        )
        serverCommunicationSystem.send(intArrayOf(receiverContext.sender), tomMessage)
    }

    /**
     * Method called by the polynomial generation manager when the requested random number is generated
     * @param context Random number share and its context
     */
    override fun onRandomPolynomialsCreation(context: RandomPolynomialContext) {
        lock.lock()
        val delta = context.time / 1000000.0
        logger.debug("Received random number polynomial with id {} in {} ms", context.id, delta)
        val messageContext: MessageContext = requests.remove(context.id)!!
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

    private fun signAndSend(
        receiverContext: MessageContext,
        data: ByteArray,
        signingPrivateKeyShare: VerifiableShare,
        randomPrivateKeyShare: VerifiableShare,
        randomPublicKey: ECPoint
    ) {
        val sigma = schnorrSignatureScheme.computePartialSignature(
            data,
            signingPrivateKeyShare.share.share,
            randomPrivateKeyShare.share.share,
            randomPublicKey
        ).add(if (serviceReplica.id == 0) BigInteger.ONE else BigInteger.ZERO)

        val publicPartialSignature = PublicPartialSignature(
            signingPrivateKeyShare.commitments as EllipticCurveCommitment,
            randomPrivateKeyShare.commitments as EllipticCurveCommitment,
            randomPublicKey
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
        logger.info("Sent partial signature for client {}", receiverContext.sender)
    }


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