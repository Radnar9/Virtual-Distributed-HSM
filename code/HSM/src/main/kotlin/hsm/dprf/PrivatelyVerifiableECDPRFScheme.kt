package hsm.dprf

import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.math.ec.ECPoint
import org.slf4j.LoggerFactory
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import vss.polynomial.Polynomial
import vss.secretsharing.Share
import java.io.ByteArrayInputStream
import java.io.ObjectInputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

class PrivatelyVerifiableECDPRFScheme(
    private val generator: ECPoint,
    private val curve: ECCurve,
    private val threshold: Int
) {
    private val logger = LoggerFactory.getLogger("dprf")
    private val field = curve.order
    private val rndGenerator = SecureRandom()
    private val digest: MessageDigest = MessageDigest.getInstance("SHA-256")
    private val ellipticCurveCommitment = EllipticCurveCommitment(curve)

    fun initTesting(shareholders: Array<BigInteger>): DPRFParameters {
        val secretKey = getRandomNumber()
        val polynomial = Polynomial(field, threshold, secretKey, rndGenerator)
        val privateParameters: MutableMap<BigInteger, DPRFPrivateParameters> = HashMap(shareholders.size)
        val secretKeyShareCommitments: MutableMap<BigInteger, BigInteger> = HashMap(shareholders.size)
        for (shareholder in shareholders) {
            val secretKeyShare = polynomial.evaluateAt(shareholder)
            secretKeyShareCommitments[shareholder] = BigInteger(generator.multiply(secretKeyShare).getEncoded(true))
            privateParameters[shareholder] = DPRFPrivateParameters(secretKeyShare)
        }
        val secretKeyCommitment = generator.multiply(secretKey).getEncoded(true)
        val publicParameters = DPRFPublicParameters(
            BigInteger(generator.getEncoded(true)),
            BigInteger(secretKeyCommitment),
            secretKeyShareCommitments
        )
        return DPRFParameters(publicParameters, privateParameters)
    }

    fun initTesting(shares: List<Share>, commitment: BigInteger): DPRFParameters {
        val commitments = deserializeCommitments(commitment)
        return DPRFParameters(
            DPRFPublicParameters(
                BigInteger(generator.getEncoded(true)),
                BigInteger(commitments[commitments.size - 1].getEncoded(true)),
                buildMap { shares.forEach { share -> put(share.shareholder, BigInteger(commitments[commitments.size - 1].getEncoded(true))) } }
            ),
            buildMap { shares.forEach { share -> put(share.shareholder, DPRFPrivateParameters(share.share)) } }
        )
    }

    fun init(share: Share, commitment: BigInteger): DPRFParameters {
        val publicParameters = DPRFPublicParameters(BigInteger(generator.getEncoded(true)), commitment, mapOf(share.shareholder to commitment))
        val privateParameters = mapOf(share.shareholder to DPRFPrivateParameters(share.share))
        return DPRFParameters(publicParameters, privateParameters)
    }

    fun contribute(
        shareholder: BigInteger,
        x: BigInteger,
        publicParameters: DPRFPublicParameters,
        privateParameters: DPRFPrivateParameters,
    ): DPRFContribution {
        val secretKeyShare = privateParameters.getSecretKeyShare()
        val secretKeyShareCommitment = curve.decodePoint(publicParameters.getSecretKeyShareCommitmentOf(shareholder).toByteArray())
        val w = generator.multiply(x)
        val h = w.multiply(secretKeyShare)
        val v = getRandomNumber()
        val t = w.multiply(v)
        val c = BigInteger(
            hash(
                h.getEncoded(true),
                w.getEncoded(true),
                secretKeyShareCommitment.getEncoded(true),
                generator.getEncoded(true),
                t.getEncoded(true)
            )
        )
        val u = v.subtract(c.multiply(secretKeyShare)).mod(field)
        return DPRFContribution(BigInteger(h.getEncoded(true)), c, u)
    }

    fun evaluate(
        x: BigInteger,
        shareholders: Array<BigInteger>,
        publicParameters: DPRFPublicParameters,
        contributions: Array<DPRFContribution>,
    ): BigInteger? {
        require(contributions.size == shareholders.size) { "Number of shareholders and contributions must be equal." }
        require(contributions.size > threshold) { "Number of contributions must be more than the threshold amount." }
        val w = generator.multiply(x)
        for (i in contributions.indices) {
            val contribution = contributions[i]
            val secretKeyShareCommitment = curve.decodePoint(publicParameters.getSecretKeyShareCommitmentOf(shareholders[i]).toByteArray())
            val h = curve.decodePoint(contribution.h.toByteArray())
            val c = contribution.c
            val u = contribution.u
            val t = w.multiply(u).add(h.multiply(c))
            val hash = BigInteger(
                hash(
                    h.getEncoded(true),
                    w.getEncoded(true),
                    secretKeyShareCommitment.getEncoded(true),
                    generator.getEncoded(true),
                    t.getEncoded(true)
                )
            )
            if (c != hash) {
                logger.error("Contribution from shareholder {} is invalid.", shareholders[i])
                return null
            }
        }

        val lagrangeCoefficients = computeLagrangeCoefficients(shareholders)
        var secret = curve.infinity
        for (i in shareholders.indices) {
            val v = curve.decodePoint(contributions[i].h.toByteArray()).multiply(lagrangeCoefficients[i])
            secret = secret.add(v)
        }
        return BigInteger(secret.getEncoded(true))
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

    private fun deserializeCommitments(commitment: BigInteger): Array<ECPoint> {
        ByteArrayInputStream(commitment.toByteArray()).use { bis ->
            ObjectInputStream(bis).use { `in` ->
                ellipticCurveCommitment.readExternal(`in`)
            }
        }
        return ellipticCurveCommitment.commitment
    }

    internal fun getRandomNumber(): BigInteger {
        val numBits = field.bitLength() - 1
        var rndBig = BigInteger(numBits, rndGenerator)
        if (rndBig.compareTo(BigInteger.ZERO) == 0) {
            rndBig = rndBig.add(BigInteger.ONE)
        }
        return rndBig
    }
}
