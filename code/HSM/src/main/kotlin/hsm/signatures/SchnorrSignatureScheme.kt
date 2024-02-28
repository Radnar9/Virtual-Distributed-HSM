package hsm.signatures

import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.math.ec.ECPoint
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import vss.facade.SecretSharingException
import vss.interpolation.InterpolationStrategy
import vss.interpolation.LagrangeInterpolation
import vss.polynomial.Polynomial
import vss.secretsharing.Share
import java.math.BigInteger
import java.security.MessageDigest

class SchnorrSignatureScheme {
    private val messageDigest: MessageDigest = MessageDigest.getInstance("SHA256")
    private val generator: ECPoint
    private val order: BigInteger
    private val corruptedShareholders: MutableSet<BigInteger>
    private val interpolationStrategy: InterpolationStrategy
    private val curve: ECCurve

    init {
        // secp256r1 curve domain parameters
        val prime = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
        order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        val a = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
        val b = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
        val compressedGenerator = BigInteger("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16).toByteArray()

        val cofactor = prime.divide(order)
        curve = ECCurve.Fp(prime, a, b, order, cofactor)
        generator = curve.decodePoint(compressedGenerator)
        corruptedShareholders = HashSet()
        interpolationStrategy = LagrangeInterpolation(order)
    }

    fun getGenerator() = generator

    fun getCurve() = curve

    fun clearCorruptedShareholderList() {
        corruptedShareholders.clear()
    }

    fun computeSignature(
        data: ByteArray,
        signingPrivateKey: BigInteger,
        signingPublicKey: ECPoint,
        randomPrivateKey: BigInteger,
        randomPublicKey: ECPoint
    ): SchnorrSignature {
        val hash = BigInteger(computeHash(data, randomPublicKey.getEncoded(true)))      // e = H(M||X) -> X = a^r
        val sigma = randomPrivateKey.add(hash.multiply(signingPrivateKey)).mod(order)   // y = (r + s*e) mod q
        return SchnorrSignature(sigma.toByteArray(), signingPublicKey.getEncoded(true), randomPublicKey.getEncoded(true))
    }

    fun computePartialSignature(
        data: ByteArray,
        signingKeyShare: BigInteger,
        randomKeyShare: BigInteger,
        randomPublicKey: ECPoint
    ): BigInteger {
        val hash = BigInteger(computeHash(data, randomPublicKey.getEncoded(true)))
        return randomKeyShare.add(hash.multiply(signingKeyShare))
    }

    fun combinePartialSignatures(
        f: Int,
        data: ByteArray,
        signingKeyCommitment: EllipticCurveCommitment,
        randomKeyCommitment: EllipticCurveCommitment,
        signingPublicKey: ECPoint,
        randomPublicKey: ECPoint,
        vararg partialSignatures: Share
    ): SchnorrSignature {
        var minimumShares = arrayOfNulls<Share>(if (corruptedShareholders.size < f) f + 2 else f + 1)
        var i = 0
        var j = 0
        while (i < partialSignatures.size && j < minimumShares.size) {
            val share = partialSignatures[i++]
            if (!corruptedShareholders.contains(share.shareholder)) minimumShares[j++] = share
        }

        val sigmaPolynomial = Polynomial(order, minimumShares)
        if (sigmaPolynomial.degree == f) {
            return SchnorrSignature(sigmaPolynomial.constant.toByteArray(), signingPublicKey.getEncoded(true), randomPublicKey.getEncoded(true))
        }

        val hash = BigInteger(computeHash(data, randomPublicKey.getEncoded(true)))
        minimumShares = arrayOfNulls(f + 1)
        var counter = 0
        for (partialSignature in partialSignatures) {
            if (corruptedShareholders.contains(partialSignature.shareholder)) {
                continue
            }
            val isValid = verifyPartialSignature(
                hash,
                partialSignature,
                signingKeyCommitment.commitment,
                randomKeyCommitment.commitment
            )
            if (counter <= f && isValid) {
                minimumShares[counter++] = partialSignature
            }
            if (!isValid) {
                corruptedShareholders.add(partialSignature.shareholder)
            }
        }

        if (counter <= f) {
            throw SecretSharingException("Not enough valid shares!")
        }
        val sigma = interpolationStrategy.interpolateAt(BigInteger.ZERO, minimumShares)

        return SchnorrSignature(sigma.toByteArray(), signingPublicKey.getEncoded(true), randomPublicKey.getEncoded(true))
    }

    fun verifySignature(
        data: ByteArray,
        signingPublicKey: ECPoint,
        randomPublicKey: ECPoint,
        sigma: BigInteger
    ): Boolean {
        if (sigma >= order) return false
        val hash = BigInteger(computeHash(data, randomPublicKey.getEncoded(true)))

        val leftSide = generator.multiply(sigma)                                // g*E -> E(sigma) = y = (r + s*e) mod q
        val rightSide = randomPublicKey.add(signingPublicKey.multiply(hash))    // X + v*e -> e = H(M||X)
        return leftSide.equals(rightSide)
    }

    private fun verifyPartialSignature(
        hash: BigInteger,
        partialSignature: Share,
        secretKeyCommitment: Array<ECPoint>,
        randomSecretCommitment: Array<ECPoint>
    ): Boolean {
        val leftSide = generator.multiply(partialSignature.share)
        var combinedSecretKeyCommitment = secretKeyCommitment[secretKeyCommitment.size - 1]
        var combinedRandomSecretCommitment = randomSecretCommitment[randomSecretCommitment.size - 1]
        val shareholder = partialSignature.shareholder
        for (i in 0..<secretKeyCommitment.size - 1) {
            val k = secretKeyCommitment.size - 1 - i
            combinedSecretKeyCommitment = combinedSecretKeyCommitment.add(
                secretKeyCommitment[i].multiply(shareholder.pow(k))
            )
            combinedRandomSecretCommitment = combinedRandomSecretCommitment.add(
                randomSecretCommitment[i].multiply(shareholder.pow(k))
            )
        }
        val rightSide = combinedRandomSecretCommitment.add(combinedSecretKeyCommitment.multiply(hash))
        return leftSide.equals(rightSide)
    }

    private fun computeHash(vararg contents: ByteArray): ByteArray {
        for (content in contents) {
            messageDigest.update(content)
        }
        return messageDigest.digest()
    }

    fun decodePublicKey(encodedKey: ByteArray): ECPoint {
        return curve.decodePoint(encodedKey)
    }

    fun encodePublicKey(publicKey: ECPoint): ByteArray {
        return publicKey.getEncoded(true)
    }
}