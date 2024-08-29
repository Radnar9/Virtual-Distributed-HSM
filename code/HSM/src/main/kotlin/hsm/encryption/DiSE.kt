package hsm.encryption

import confidential.EllipticCurveConstants
import confidential.EllipticCurveParameters
import hsm.communications.readByteArray
import hsm.communications.writeByteArray
import hsm.dprf.*
import org.bouncycastle.math.ec.ECCurve
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import vss.commitment.ellipticCurve.EllipticCurveCommitmentScheme
import vss.polynomial.Polynomial
import vss.secretsharing.Share
import java.io.*
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


private data class PreCommittedData(val data: ByteArray, val p: ByteArray)

class DiSE(
    val shareholderId: BigInteger, // Starts at 1
    val threshold: Int,
    ecParams: EllipticCurveParameters,
    seed: ByteArray? = "DiSE-HSM".toByteArray(),
    secretKey: BigInteger? = null,
) {
    // setup: (1^k, n, t) -> ([sk]n, pp)
    private val prng = SecureRandom(seed)
    private val defaultBitLen = 16 * 8 - 1
    private val secretKey = secretKey ?: getRandomNumber(defaultBitLen)
    private val digest = MessageDigest.getInstance("SHA3-256")
    private val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

    private val curve = ECCurve.Fp(ecParams.prime(), ecParams.a(), ecParams.b(), ecParams.order(), ecParams.cofactor())
    private val generator = curve.createPoint(ecParams.x(), ecParams.y())

    private val dprfScheme = PrivatelyVerifiableECDPRFScheme(generator, curve, threshold)

    fun initTesting(shareholders: Array<BigInteger>): DPRFParameters {
        return dprfScheme.initTesting(shareholders)
    }

    fun initTesting(shares: List<Share>, commitment: BigInteger): DPRFParameters {
        return dprfScheme.initTesting(shares, commitment)
    }

    fun init(share: Share, commitment: BigInteger): DPRFParameters {
        return dprfScheme.init(share, commitment)
    }

    fun commitData(message: ByteArray, rho: BigInteger? = null): CommittedData {
        // Sample randomness rho for the commitment
        val p = rho ?: getRandomNumber(defaultBitLen)

        // hash the {message, rho} to get the DPRF input
        val alpha = digest.apply {
            update(message)
            update(p.toByteArray())
        }.digest()

        return CommittedData(alpha, p.toByteArray())
    }

    fun encrypt(
        message: ByteArray,
        committedData: CommittedData,
        evalData: BigInteger,
        publicParameters: DPRFPublicParameters,
        shareholders: Array<BigInteger>,
        contributions: Array<DPRFContribution>
    ): ByteArray? {
        // j combines z's into w
        val w = combineContributions(evalData, publicParameters, shareholders, contributions) ?: return null
//        println("w: ${w.toString(16)}")

        // e = PRNG(w) xor (m||p)
        val prngW = BigInteger(1, oneTimePad(w.toByteArray()))
//        println("prngW: ${prngW.toString(16)}")
        val msgRho = BigInteger(concatenateMessageAndRho(message, committedData.p))
//        println("msgRho: ${msgRho.toString(16)}")
        val e = prngW.xor(msgRho)

        // ciphertext = (j, alpha, e)
        val ciphertext = DiSECiphertext(shareholderId, committedData.alpha, e.toByteArray())

        return ciphertext.serialize()
    }

    // Used only for testing purposes
    fun eval(dprfParameters: DPRFParameters, evalData: BigInteger, shareholders: Array<BigInteger>, contributions: Array<DPRFContribution>) {
        val quorums = getQuorums(threshold)

        for (quorum in quorums) {
            println("======> Quorum: " + quorum.contentToString())
            val contributionsQuorum = ArrayList<DPRFContribution>(quorum.size)
            val shareholdersQuorum = ArrayList<BigInteger>(quorum.size)
            for (j in quorum.indices) {
                contributionsQuorum.add(contributions[quorum[j]])
                shareholdersQuorum.add(shareholders[quorum[j]])
            }
            val y = dprfScheme.evaluate(evalData, shareholdersQuorum.toTypedArray(), dprfParameters.publicParameters, contributionsQuorum.toTypedArray())
            println(y)
        }
        println()
    }

    fun parseEncryptedData(encryptedData: ByteArray) = DiSECiphertext.deserialize(encryptedData)

    fun decrypt(
        ciphertext: DiSECiphertext,
        evalData: BigInteger,
        publicParameters: DPRFPublicParameters,
        shareholders: Array<BigInteger>,
        contributions: Array<DPRFContribution>
    ): ByteArray? {
        val w = combineContributions(evalData, publicParameters, shareholders, contributions) ?: return null

        // (m || p) = PRNG(w) xor e
        val prngW = BigInteger(1, oneTimePad(w.toByteArray()))

        val msgRho = prngW.xor(BigInteger(ciphertext.encryptedData))

        val preCommittedData = decatenateMessageAndRho(msgRho.toByteArray())

        val newCommit = commitData(preCommittedData.data, BigInteger(preCommittedData.p))
        return if (newCommit.alpha.contentEquals(ciphertext.alpha))
            preCommittedData.data
        else
            null
    }

    fun performContribution(x: BigInteger, dprfParameters: DPRFParameters): DPRFContribution {
        return dprfScheme.contribute(
            shareholderId,
            x,
            dprfParameters.publicParameters,
            dprfParameters.getPrivateParameterOf(shareholderId)
        )
    }

    /**
     * x -> eval data
     */
    private fun combineContributions(x: BigInteger, publicParameters: DPRFPublicParameters, shareholders: Array<BigInteger>, contributions: Array<DPRFContribution>): BigInteger? {
        return dprfScheme.evaluate(x, shareholders, publicParameters, contributions)
    }

    private fun concatenateMessageAndRho(message: ByteArray, p: ByteArray): ByteArray {
        val concatenateData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                writeByteArray(out, message)
                writeByteArray(out, p)
                out.flush()
                bos.flush()
                concatenateData = bos.toByteArray()
            }
        }
        return concatenateData
    }

    private fun decatenateMessageAndRho(data: ByteArray): PreCommittedData {
        ByteArrayInputStream(data).use { bis ->
            ObjectInputStream(bis).use { `in` ->
                val message = readByteArray(`in`)
                val p = readByteArray(`in`)
                return PreCommittedData(message, p)
            }
        }
    }

    private fun oneTimePad(w: ByteArray): ByteArray {
        val secretKeySpec = SecretKeySpec(secretKey.toByteArray(), "AES")
        val ivParameterSpec = IvParameterSpec(secretKey.toByteArray())
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec)
        return cipher.doFinal(w)
    }

    private fun getRandomNumber(numBits: Int): BigInteger {
        var rndBig = BigInteger(numBits, prng)
        if (rndBig.compareTo(BigInteger.ZERO) == 0) {
            rndBig = rndBig.add(BigInteger.ONE)
        }
        return rndBig
    }
}

fun main() {
    val threshold = 1
    val n = 3 * threshold + 1
    val ecParams = EllipticCurveConstants.secp256r1.PARAMETERS

    val shareholders = Array<BigInteger>(n) { BigInteger.ZERO }
    val diseServers = buildList {
        for (i in 0..<n) {
            val shareholderId = BigInteger("${i + 1}")
            shareholders[i] = shareholderId
            add(DiSE(shareholderId, threshold, ecParams))
        }
    }

    val (shares, commitment) = generateSharesAndCommitment(ecParams, shareholders, threshold)

    val secret = BigInteger("3d337ac6d5b62f4e7ca85b59c377b39c", 16)
    val encryptor = DiSE(5.toBigInteger(), threshold, ecParams, secretKey = secret)
//    val dprfParameters = encryptor.initTesting(shareholders)
//    val dprfParameters = mockSharesAndCommitmentInit(encryptor)
    val dprfParameters = encryptor.initTesting(shares, serializeCommitments(commitment))

    val decryptor = DiSE(6.toBigInteger(), threshold, ecParams, secretKey = secret)

//repeat(100) {
    println("---| ENCRYPTION |---")
    val message = "This is data to be encrypted".toByteArray()
    val committedData = encryptor.commitData(message)

    // Perform contributions
    val encContributions = mutableListOf<DPRFContribution>()
    val encShareholders = mutableListOf<BigInteger>()
    val encEvalInput = BigInteger(1, "${encryptor.shareholderId}".toByteArray().plus(committedData.alpha)) // j || alpha

    for (diseServer in diseServers) {
        val contribution = diseServer.performContribution(encEvalInput, dprfParameters)
        encContributions.add(contribution)
        encShareholders.add(diseServer.shareholderId)
        println(contribution)
    }
    encryptor.eval(dprfParameters, encEvalInput, encShareholders.toTypedArray(), encContributions.toTypedArray())

    // ENCRYPTION: Performed by the encryptor
    val ciphertext = encryptor.encrypt(
        message,
        committedData,
        encEvalInput,
        dprfParameters.publicParameters,
        encShareholders.toTypedArray(),
        encContributions.toTypedArray()
    ) ?: return
    println("Encryption: ${DiSECiphertext.deserialize(ciphertext)}")

    println("---| DECRYPTION |---")
    val parsedCiphertext = decryptor.parseEncryptedData(ciphertext)
    val decEvalInput = BigInteger(1, "${parsedCiphertext.encryptorId}".toByteArray().plus(parsedCiphertext.alpha))

    // Perform contributions
    val quorums = getQuorums(threshold) /*arrayOf(intArrayOf(1, 2, 3, 4, 5))*/
    for (quorum in quorums) {
        println("======> Quorum: " + quorum.contentToString())
        val decContributions = mutableListOf<DPRFContribution>()
        val decShareholders = mutableListOf<BigInteger>()
        for (j in quorum.indices) {
            val quorumIdx = quorum[j]
            val server = diseServers[quorumIdx]
            val contribution = server.performContribution(decEvalInput, dprfParameters)
            decContributions.add(contribution)
            decShareholders.add(shareholders[quorumIdx])
        }

        // DECRYPTION: Performed by the decryptor
        val decryptedMessage = decryptor.decrypt(
            parsedCiphertext,
            decEvalInput,
            dprfParameters.publicParameters,
            decShareholders.toTypedArray(),
            decContributions.toTypedArray()
        ) ?: return

        println("[>] ${decryptedMessage.decodeToString()}")
    }

/*    val decContributions = mutableListOf<DPRFContribution>()
    val decShareholders = mutableListOf<BigInteger>()
    val quorum = listOf(1, 2, 3, 4, 5, 6)
    for (idx in quorum) {
        val server = diseServers[idx]
        val contribution = server.performContribution(decEvalInput, dprfParameters)
        decContributions.add(contribution)
        decShareholders.add(server.shareholderId)
    }*/

    // DECRYPTION: Performed by the decryptor
/*    val decryptedMessage = decryptor.decrypt(
        parsedCiphertext,
        decEvalInput,
        dprfParameters.publicParameters,
        decShareholders.toTypedArray(),
        decContributions.toTypedArray()
    ) ?: return*/
//    println(decContributions.forEach { println(it.toString()) })
//    println("Decrypted message: ${decryptedMessage.decodeToString()}")
//    println(it)
//}
}

private fun mockSharesAndCommitmentInit(dise: DiSE): DPRFParameters {
    val rawShares = listOf(
        "1c9e5ef4dfaa15359b4113c7bf0ee1c51d1c389d274bb9b766dd0b43d0d7e2ba7",
        "1ef386914679d1c985e3a7a1a55669a03f51c2bb278cbd451fdd721ba85732710",
        "2010f2befe792894e2377ad98d0a498dd61f41a785aedb0f6622b8da182f0d1b3",
        "ff6a37e07a81997b03c8d6f762a818df5d9c793d6bd89127dafb996535c0ea4f",
        "ea498ce6206a4d1eff2df6360b711a075d7301cf0a1db55de7ec021f3e4ff366",
        "1c1ad2b00d94ca43a15a70b54caff9c556177b42d35bd1d9888fcc7cf9c9decf8",
        "185951230a5289ecc47341653a1539fcbf44cd68a902589603e892d5cb03e5483",
    )
    val commitment = BigInteger("-5312fffa888cfffffffcffffffdefd7dd0b9ad08dddb1c6fdb50e4f1a61a6b6e02a8fafb79776c8f975b0da852c38bffffffdefc1e4a65eed66fd322f4b9e3b0dbcf9987ab36e849fedc58ceb00a3a86d38656c1ffffffdefcd86f760706ae5a4efa2e9e7692180b28f8d6951b4df04fee5b65c3508cb325b3", 16)
    val shares = buildList {
        rawShares.forEachIndexed { i, share -> add(Share(BigInteger("${i+1}"), BigInteger(share, 16))) }
    }
    return dise.initTesting(shares, commitment)
}

private fun getQuorums(threshold: Int): Array<IntArray> {
    val quorumsT1 = arrayOf(
        intArrayOf(0, 1, 2, 3),
        intArrayOf(1, 2, 3),
        intArrayOf(3, 0, 2),
        intArrayOf(0, 1),
        intArrayOf(1, 3),
        intArrayOf(2, 0),
    )

    val quorumsT2 = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6),
        intArrayOf(1, 2, 5, 4, 0),
        intArrayOf(1, 2, 3, 4),
        intArrayOf(3, 0, 2),
        intArrayOf(0, 1, 3),
        intArrayOf(1, 3, 2),
    )

    return if (threshold == 1) quorumsT1 else quorumsT2
}

private fun generateSharesAndCommitment(
    ecParams: EllipticCurveParameters,
    shareholders: Array<BigInteger>,
    threshold: Int,
): Pair<List<Share>, EllipticCurveCommitment> {
    val rndGenerator = SecureRandom()
    val secret = getRandomNumber(ecParams.order(), rndGenerator)
    val polynomial = Polynomial(ecParams.order(), threshold, secret, rndGenerator)
    val shares = buildList {
        shareholders.forEach { add(Share(it, polynomial.evaluateAt(it))) }
    }

    val ellipticCurveCommitmentScheme = EllipticCurveCommitmentScheme(
        ecParams.prime(),
        ecParams.order(),
        ecParams.a(),
        ecParams.b(),
        ecParams.x(),
        ecParams.y(),
        ecParams.cofactor()
    )

    val ellipticCurveCommitment = ellipticCurveCommitmentScheme.generateCommitments(polynomial) as EllipticCurveCommitment

/*    val serializedCommitment = serializeCommitments(ellipticCurveCommitment)

    val curve = ECCurve.Fp(ecParams.prime(), ecParams.a(), ecParams.b(), ecParams.order(),ecParams.cofactor())
    val deserializedCommitment = deserializeCommitment(curve, serializedCommitment)

    println("Are commitments equal? ${if (ellipticCurveCommitment == deserializedCommitment) "YES" else "NO"}")*/

    return Pair(shares, ellipticCurveCommitment)
}

private fun serializeCommitments(commitment: EllipticCurveCommitment): BigInteger {
    lateinit var commitmentBytes: ByteArray
    try {
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                commitment.writeExternal(out)
                out.flush()
                bos.flush()
                commitmentBytes = bos.toByteArray()
            }
        }
    } catch (e: IOException) {
        e.printStackTrace()
    }
    return BigInteger(commitmentBytes)
}

private fun deserializeCommitment(curve: ECCurve, serializedCommitments: BigInteger): EllipticCurveCommitment {
    val ellipticCurveCommitment = EllipticCurveCommitment(curve)
    ByteArrayInputStream(serializedCommitments.toByteArray()).use { bis ->
        ObjectInputStream(bis).use { `in` ->
            ellipticCurveCommitment.readExternal(`in`)
        }
    }
    return ellipticCurveCommitment
}

private fun getRandomNumber(field: BigInteger, rndGenerator: SecureRandom): BigInteger {
    val numBits = field.bitLength() - 1
    var rndBig = BigInteger(numBits, rndGenerator)
    if (rndBig.compareTo(BigInteger.ZERO) == 0) {
        rndBig = rndBig.add(BigInteger.ONE)
    }
    return rndBig
}