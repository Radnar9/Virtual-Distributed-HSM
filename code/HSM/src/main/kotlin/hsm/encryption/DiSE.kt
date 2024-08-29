package hsm.encryption

import confidential.EllipticCurveParameters
import hsm.communications.readByteArray
import hsm.communications.writeByteArray
import hsm.dprf.*
import org.bouncycastle.math.ec.ECCurve
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
