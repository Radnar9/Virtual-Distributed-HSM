package hsm.signatures

import confidential.EllipticCurveParameters
import java.math.BigInteger

object ECParameters {
    val secp256k1 = ecParameters(
        curveName = "secp256k1",
        prime = BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
        order = BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
        a = BigInteger("0", 16),
        b = BigInteger("7", 16),
        x = BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
        y = BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
        cofactor = BigInteger("1", 16),
    )

    val BLS12_381 = ecParameters(
        curveName = "BLS12_381",
        prime = BigInteger("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16),
        order = BigInteger("73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001", 16),
        a = BigInteger("0", 16),
        b = BigInteger("4", 16),
        x = BigInteger("17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB", 16),
        y = BigInteger("08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1", 16),
        cofactor = BigInteger("396C8C005555E1568C00AAAB0000AAAB", 16),
    )

    private fun ecParameters(
        curveName: String,
        prime: BigInteger,
        order: BigInteger,
        a: BigInteger,
        b: BigInteger,
        x: BigInteger,
        y: BigInteger,
        cofactor: BigInteger
    ): EllipticCurveParameters {
        return EllipticCurveParameters(curveName, prime, order, a, b, x, y, cofactor)
    }
}