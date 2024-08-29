package hsm.dprf

import org.bouncycastle.math.ec.ECCurve
import vss.secretsharing.Share
import java.math.BigInteger


fun main() {
    //secp256r1 curve domain parameters
    val prime = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
    val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    val a = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
    val b = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
    val compressedGenerator = BigInteger("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16).toByteArray()

    val cofactor = prime.divide(order)
    val curve: ECCurve = ECCurve.Fp(prime, a, b, order, cofactor)
    val generator = curve.decodePoint(compressedGenerator)

    val t = 2
    val n = 3 * t + 1

    val shareholders = Array<BigInteger>(n) { BigInteger.ZERO }
    for (i in 0..<n) {
        shareholders[i] = BigInteger("${i + 1}")
    }

    // Initialize the DPRF scheme
    val dprfScheme = PrivatelyVerifiableECDPRFScheme(generator, curve, t)

    // Initialize key shares
    val dprfParameters: DPRFParameters = dprfScheme.initTesting(shareholders)

    // Perform contributions
    val x = dprfScheme.getRandomNumber()
    println("x: $x")

    val shares = ArrayList<Share>(n)
    val contributions = ArrayList<DPRFContribution>(shareholders.size)
    for (i in shareholders.indices) {
        val shareholder = shareholders[i]
        val privateParameters = dprfParameters.getPrivateParameterOf(shareholder)
        shares.add(Share(shareholder, privateParameters.getSecretKeyShare()))
        contributions.add(dprfScheme.contribute(shareholder, x, dprfParameters.publicParameters, privateParameters))
        println("Shareholder ${shareholders[i]}: ${contributions[i]}")
    }
    println()

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

    val quorums = if (t == 1) quorumsT1 else quorumsT2

    for (quorum in quorums) {
        println("======> Quorum: " + quorum.contentToString())
        val contributionsQuorum = ArrayList<DPRFContribution>(quorum.size)
        val shareholdersQuorum = ArrayList<BigInteger>(quorum.size)
        for (j in quorum.indices) {
            contributionsQuorum.add(contributions[quorum[j]])
            shareholdersQuorum.add(shareholders[quorum[j]])
        }
        val y = dprfScheme.evaluate(x, shareholdersQuorum.toTypedArray(), dprfParameters.publicParameters, contributionsQuorum.toTypedArray())
        println(y)
    }
}
