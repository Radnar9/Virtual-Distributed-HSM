package hsm.dprf

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import vss.polynomial.Polynomial
import vss.secretsharing.Share
import vss.secretsharing.VerifiableShare
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.ObjectOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom


class PrivatelyVerifiableDPRFScheme(
    private val id: BigInteger,
    private val primeField: BigInteger,
    private val field: BigInteger,
    private val generator: BigInteger,
    private val threshold: Int,
) {
    private val logger: Logger = LoggerFactory.getLogger("dprf")
    private val rndGenerator = SecureRandom()
    private val digest: MessageDigest = MessageDigest.getInstance("SHA-256")

    fun init(shareholders: Array<BigInteger>, privateKeyShare: VerifiableShare? = null): DPRFParameters {
        if (privateKeyShare == null) {
            val secretKey = getRandomNumber()
            val polynomial = Polynomial(field, threshold, secretKey, rndGenerator)
            val privateParameters: MutableMap<BigInteger, DPRFPrivateParameters> = HashMap(shareholders.size)
            val secretKeyShareCommitments: MutableMap<BigInteger, BigInteger> = HashMap(shareholders.size)
            for (shareholder in shareholders) {
                val secretKeyShare = polynomial.evaluateAt(shareholder)
                secretKeyShareCommitments[shareholder] = generator.modPow(secretKeyShare, primeField)
                privateParameters[shareholder] = DPRFPrivateParameters(secretKeyShare)
            }
            val secretKeyCommitment = generator.modPow(secretKey, primeField)
            val publicParameters = DPRFPublicParameters(generator, secretKeyCommitment, secretKeyShareCommitments)
            return DPRFParameters(publicParameters, privateParameters)
        }
        val commitment = privateKeyShare.commitments as EllipticCurveCommitment
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
        val mockShares = listOf(
            "145684c44d0b0b0651dc753016853cf153838d2c2500ec0986ba1a24e6706fc5c",
            "101f92a90f1b96a44d8446fbc884c471e5e1556e9676deee8b71295a52ae3a537",
            "be8a08dd12c2242492c18c77a844bf2783f1db107ecd1d39028388fbeec04e12",
            "7b1ae72933cade044d3ea932c83d3730a9ce5f37962c4b894df47c52b29cf6ed",
        )
        val mockCommitment = "5312fffa88b1fffffffdffffffdefdce1435c4a8aae940a392fa819e4421e89b1c32598b2a7a4b355515997eb14fa4ffffffdefcbb702bd3c88c105185e500bc92a65582670b86832dffac5e678dae48436ac460"
        println("Commitment: ${BigInteger(commitmentBytes).toString(16)}")
        return DPRFParameters(
            DPRFPublicParameters(generator, generator.modPow(getRandomNumber(), primeField), mapOf(id to BigInteger(commitmentBytes/*mockCommitment, 16*/))),
            mapOf(id to DPRFPrivateParameters(privateKeyShare.share.share/*BigInteger(mockShares[id.toInt()], 16)*/))
        )
    }

    fun init(shares: List<Share>, commitment: BigInteger): DPRFParameters {
        return DPRFParameters(
            DPRFPublicParameters(
                generator,
                generator.modPow(getRandomNumber(), primeField),
                buildMap { shares.forEach { share -> put(share.shareholder, commitment) } }
            ),
            buildMap { shares.forEach { share -> put(share.shareholder, DPRFPrivateParameters(share.share)) } }
        )
    }

    fun contribute(
        shareholder: BigInteger,
        x: BigInteger,
        publicParameters: DPRFPublicParameters,
        privateParameters: DPRFPrivateParameters
    ): DPRFContribution {
        val secretKeyShare: BigInteger = privateParameters.getSecretKeyShare()
        val secretKeyShareCommitment: BigInteger = publicParameters.getSecretKeyShareCommitmentOf(shareholder)
        val w = generator.modPow(x, primeField)
        val h = w.modPow(secretKeyShare, primeField)
        val v = getRandomNumber()
        val t = w.modPow(v, primeField)
        val c = BigInteger(
            hash(
                h.toByteArray(), w.toByteArray(), secretKeyShareCommitment.toByteArray(),
                generator.toByteArray(), t.toByteArray()
            )
        )
        val u = v.subtract(c.multiply(secretKeyShare)).mod(field)
        return DPRFContribution(h, c, u)
    }

    fun evaluate(
        x: BigInteger,
        shareholders: Array<BigInteger>,
        publicParameters: DPRFPublicParameters,
        contributions: Array<DPRFContribution>
    ): BigInteger? {
        require(contributions.size == shareholders.size) { "Number of shareholders and contributions must be equal." }
        require(contributions.size > threshold) { "Number of contributions must be more than the threshold amount." }
        val w = generator.modPow(x, primeField)
        for (i in contributions.indices) {
            val contribution = contributions[i]
            val secretKeyShareCommitment = publicParameters.getSecretKeyShareCommitmentOf(shareholders[i])
            val h = contribution.h
            val c = contribution.c
            val u = contribution.u
            val t = w.modPow(u, primeField).multiply(h.modPow(c, primeField)).mod(primeField)
            val hash = BigInteger(
                hash(
                    h.toByteArray(), w.toByteArray(), secretKeyShareCommitment.toByteArray(), generator.toByteArray(), t.toByteArray()
                )
            )
            if (c != hash) {
                logger.error("Contribution from shareholder {} is invalid.", shareholders[i])
                return null
            }
        }
        val lagrangeCoefficients = computeLagrangeCoefficients(shareholders)
        var secret = BigInteger.ONE
        for (i in shareholders.indices) {
            val v = contributions[i].h.modPow(lagrangeCoefficients[i], primeField)
            secret = secret.multiply(v).mod(primeField)
        }
        return secret
    }

    private fun computeLagrangeCoefficients(shareholders: Array<BigInteger>): Array<BigInteger> {
        val lagrangeCoefficients = Array<BigInteger>(shareholders.size) { BigInteger.ZERO }
        for (i in shareholders.indices) {
            val xi = shareholders[i]
            var numerator = BigInteger.ONE
            var denominator = BigInteger.ONE
            for (j in shareholders.indices) {
                if (i != j) {
                    val xj = shareholders[j]
                    numerator = numerator.multiply(BigInteger.ZERO.subtract(xj)).mod(field)
                    denominator = denominator.multiply(xi.subtract(xj)).mod(field)
                }
            }
            lagrangeCoefficients[i] = numerator.multiply(denominator.modInverse(field)).mod(field)
        }
        return lagrangeCoefficients
    }

    private fun hash(vararg data: ByteArray): ByteArray {
        for (datum in data) {
            digest.update(datum)
        }
        return digest.digest()
    }

    fun getRandomNumber(): BigInteger {
        val numBits = field.bitLength() - 1
        var rndBig = BigInteger(numBits, rndGenerator)
        if (rndBig.compareTo(BigInteger.ZERO) == 0) {
            rndBig = rndBig.add(BigInteger.ONE)
        }
        return rndBig
    }
}
