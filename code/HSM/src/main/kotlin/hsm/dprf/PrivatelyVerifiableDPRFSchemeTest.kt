package hsm.dprf

import confidential.EllipticCurveParameters
import org.bouncycastle.math.ec.ECCurve
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import vss.commitment.ellipticCurve.EllipticCurveCommitmentScheme
import vss.polynomial.Polynomial
import vss.secretsharing.Share
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.ObjectOutputStream
import java.math.BigInteger
import java.security.SecureRandom


private val primeField = BigInteger(
    "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597",
    16
)
private val field = BigInteger("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3", 16)
private val generator = BigInteger(
    "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659",
    16
)


private object secp256r1 {
    const val NAME = "secp256r1"
    val PRIME = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
    val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    val A = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
    val B = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
    val X = BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
    val Y = BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
    val COFACTOR = BigInteger("1", 16) // Also known as 'h'
    val PARAMETERS = EllipticCurveParameters(
        NAME, PRIME, ORDER, A, B, X, Y, COFACTOR
    )
//    val CURVE = ECCurve.Fp(PRIME, A, B, ORDER, COFACTOR)
//    val GENERATOR = BigInteger(CURVE.createPoint(X, Y).getEncoded(true))
    val GENERATOR = BigInteger("36b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
}
private val commitmentScheme = EllipticCurveCommitmentScheme(
    secp256r1.PRIME,
    secp256r1.ORDER,
    secp256r1.A,
    secp256r1.B,
    secp256r1.X,
    secp256r1.Y,
    secp256r1.COFACTOR
)
fun main() {
    val rawShares = listOf(
        "1c9e5ef4dfaa15359b4113c7bf0ee1c51d1c389d274bb9b766dd0b43d0d7e2ba7",
        "1ef386914679d1c985e3a7a1a55669a03f51c2bb278cbd451fdd721ba85732710",
        "2010f2befe792894e2377ad98d0a498dd61f41a785aedb0f6622b8da182f0d1b3",
        "ff6a37e07a81997b03c8d6f762a818df5d9c793d6bd89127dafb996535c0ea4f",
        "ea498ce6206a4d1eff2df6360b711a075d7301cf0a1db55de7ec021f3e4ff366",
        "1c1ad2b00d94ca43a15a70b54caff9c556177b42d35bd1d9888fcc7cf9c9decf8",
        "185951230a5289ecc47341653a1539fcbf44cd68a902589603e892d5cb03e5483",
        //---
//        "145684c44d0b0b0651dc753016853cf153838d2c2500ec0986ba1a24e6706fc5c",
//        "101f92a90f1b96a44d8446fbc884c471e5e1556e9676deee8b71295a52ae3a537",
//        "be8a08dd12c2242492c18c77a844bf2783f1db107ecd1d39028388fbeec04e12",
//        "7b1ae72933cade044d3ea932c83d3730a9ce5f37962c4b894df47c52b29cf6ed",
//        "37abc57554d397e407bbc5ede835af39cfaae35ead8b79d999656fa976799fc8",
//        "f43ca3c075dc51c4c238e2a9082e2742b26e62336c0246aed8902dc336b96df4",
//        "b0cd820c96e50ba47cb5ff6428269f4bd84ae65a836174ff24012119fa9616cf",
        //---
    )
    val commitment = BigInteger("-5312fffa888cfffffffcffffffdefd7dd0b9ad08dddb1c6fdb50e4f1a61a6b6e02a8fafb79776c8f975b0da852c38bffffffdefc1e4a65eed66fd322f4b9e3b0dbcf9987ab36e849fedc58ceb00a3a86d38656c1ffffffdefcd86f760706ae5a4efa2e9e7692180b28f8d6951b4df04fee5b65c3508cb325b3", 16)
//    val commitment = BigInteger("5312fffa88b1fffffffdffffffdefdce1435c4a8aae940a392fa819e4421e89b1c32598b2a7a4b355515997eb14fa4ffffffdefcbb702bd3c88c105185e500bc92a65582670b86832dffac5e678dae48436ac460", 16)
    val shares = buildList {
        rawShares.forEachIndexed { i, share -> add(Share(BigInteger("${i+1}"), BigInteger(share, 16))) }
    }
//    val rndGenerator = SecureRandom()
//    val secret = getRandomNumber(secp256r1.ORDER, rndGenerator)
//    val polynomial = Polynomial(secp256r1.ORDER, 2, secret, rndGenerator)
//    val newShares = generateNewShares(polynomial, 7)
//    val commitment = generateCommitments(polynomial)
//    println("secret: " + secret.toString(16))
//    println("commitment: " + commitment.toString(16))
//    newShares.forEach { println("${it.shareholder}: ${it.share.toString(16)}") }
//    println("gen: " + secp256r1.GENERATOR.toString(16))
    testDprf(shares, commitment)
    println()
//    testPoly(shares, commitment)
}

private fun  testDprf(shares: List<Share>, commitment: BigInteger) {
    val t = 2
    val n = 3 * t + 1

    val shareholders = ArrayList<BigInteger>(n)
    for (i in 0 until n) {
        shareholders.add(i, (i + 1).toBigInteger())
    }

    //Initialize the DPRF scheme
//    val dprfScheme = PrivatelyVerifiableDPRFScheme(1.toBigInteger(), secp256r1.PRIME, secp256r1.ORDER, secp256r1.GENERATOR, t)
    val dprfScheme = PrivatelyVerifiableDPRFScheme(1.toBigInteger(), primeField, field, generator, t)

    //Initialize key shares
//    val dprfParameters = dprfScheme.init(shareholders.toTypedArray())
    val dprfParameters = dprfScheme.init(shares, commitment)

    //share
//    val x = dprfScheme.getRandomNumber()
    val x = BigInteger("351290e21404a5f71a489ccee091a854dde9bdf0d1a97e6612a1fdbb1684308217", 16)
    println("\nx: $x")

    val contributions = ArrayList<DPRFContribution>(shareholders.size)
    for (i in shareholders.indices) {
        val shareholder = shareholders[i]
        val privateParameters = dprfParameters.getPrivateParameterOf(shareholder)
        contributions.add(dprfScheme.contribute(shareholder, x, dprfParameters.publicParameters, privateParameters))
        println("Shareholder $shareholder contribution: ${contributions[i]}")
    }
    println()

    val quorums = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6),
        intArrayOf(0, 1, 2, 3, 4),
        intArrayOf(0, 1, 6, ),
//        intArrayOf(0, 1, 2, 3),
//        intArrayOf(0, 1),
        /*        intArrayOf(2, 3),
                intArrayOf(1, 2),
                intArrayOf(1, 3),
                intArrayOf(0, 2),
                intArrayOf(0, 1, 2),
                intArrayOf(3, 1, 2),*/
    )
    for (quorum in quorums) {
        println("======> Quorum: " + quorum.contentToString())
        val contributionsQuorum = ArrayList<DPRFContribution>(quorum.size)
        val shareholdersQuorum = ArrayList<BigInteger>(quorum.size)
        for (j in quorum.indices) {
            contributionsQuorum.add(contributions[quorum[j]])
            shareholdersQuorum.add(shareholders[quorum[j]])
        }
        val y: BigInteger? = dprfScheme.evaluate(x, shareholdersQuorum.toTypedArray(), dprfParameters.publicParameters, contributionsQuorum.toTypedArray())
        println(y)
    }
}

private fun testPoly(shares: List<Share>, commitment: BigInteger) {
    /*val rawShares = listOf(
        "1c9e5ef4dfaa15359b4113c7bf0ee1c51d1c389d274bb9b766dd0b43d0d7e2ba7",
        "1ef386914679d1c985e3a7a1a55669a03f51c2bb278cbd451fdd721ba85732710",
        "2010f2befe792894e2377ad98d0a498dd61f41a785aedb0f6622b8da182f0d1b3",
        "ff6a37e07a81997b03c8d6f762a818df5d9c793d6bd89127dafb996535c0ea4f",
        "ea498ce6206a4d1eff2df6360b711a075d7301cf0a1db55de7ec021f3e4ff366",
        "1c1ad2b00d94ca43a15a70b54caff9c556177b42d35bd1d9888fcc7cf9c9decf8",
        "185951230a5289ecc47341653a1539fcbf44cd68a902589603e892d5cb03e5483"
    )
    val commitment = BigInteger("-5312fffa888cfffffffcffffffdefd7dd0b9ad08dddb1c6fdb50e4f1a61a6b6e02a8fafb79776c8f975b0da852c38bffffffdefc1e4a65eed66fd322f4b9e3b0dbcf9987ab36e849fedc58ceb00a3a86d38656c1ffffffdefcd86f760706ae5a4efa2e9e7692180b28f8d6951b4df04fee5b65c3508cb325b3", 16)

    val shares = buildList {
        rawShares.forEachIndexed { i, share -> add(Share(BigInteger("${i+1}"), BigInteger(share, 16))) }
    }*/
    val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    val polynomial = Polynomial(order, shares.toTypedArray())

    println(polynomial.toString())
    println("Expect: 88d76df9afa7f684634a3646485b570c557553ed9197f3c32c76e434a6c72e30")
    println("Result: ${polynomial.constant.toString(16)}")

    shares.forEach { share -> println("${share.shareholder}: ${polynomial.evaluateAt(share.shareholder).toString(16)}") }
//    println(polynomial.evaluateAt(6.toBigInteger()).toString(16))

}

private fun getRandomNumber(field: BigInteger, rndGenerator: SecureRandom): BigInteger {
    val numBits = field.bitLength() - 1
    var rndBig = BigInteger(numBits, rndGenerator)
    if (rndBig.compareTo(BigInteger.ZERO) == 0) {
        rndBig = rndBig.add(BigInteger.ONE)
    }
    return rndBig
}

private fun generateNewShares(polynomial: Polynomial, n: Int): List<Share> {
    return buildList {
        (0..<n).forEach {
            val shareholder = BigInteger("${it+1}")
            add(Share(shareholder, polynomial.evaluateAt(shareholder)))
        }
    }
}

private fun generateCommitments(polynomial: Polynomial): BigInteger {
    val commitment = commitmentScheme.generateCommitments(polynomial) as EllipticCurveCommitment
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