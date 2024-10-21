package hsm.signatures.schnorr

import hsm.client.printStats
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.system.measureTimeMillis

class LocalSchnorr {
    // KeyPair class to hold private and public keys
    private data class KeyPair(val privateKey: BigInteger, val publicKey: BigInteger)
    // Signature class to hold the signature values
    private data class Signature(val s: BigInteger, val e: BigInteger)

    private val random = SecureRandom()
    private val p = BigInteger("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597",16)
    private val g = BigInteger("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659",16)

    fun performSignAndValidation() {
        val message = "SignThisMessage"

        // Generate keys
        val keyPair = generateKeyPair()
        // Sign the message
        val signature = sign(message, keyPair.privateKey)
        // Verify the signature
        val isValid = verify(message, signature, keyPair.publicKey)
        println("Signature valid: $isValid")
    }

    fun testSignature(times: Int) {
        println("* Testing local Schnorr signature: STARTING")
        val executionTimes = DoubleArray(times)

        val message = "SignThisMessage"
        val keyPair = generateKeyPair()
        repeat(times) {
            val millis = measureTimeMillis {
                sign(message, keyPair.privateKey)
            }
            executionTimes[it] = millis.toDouble()
            println("$it:\t${millis / 1000.0} s")
        }
        println("* Testing local Schnorr signature: DONE\n")
        printStats(executionTimes)
    }

    fun testSignatureValidation(times: Int) {
        println("* Testing local Schnorr signature validation: STARTING")
        val executionTimes = DoubleArray(times)

        val message = "SignThisMessage"
        val keyPair = generateKeyPair()
        val signature = sign(message, keyPair.privateKey)

        repeat(times) {
            val millis = measureTimeMillis {
                verify(message, signature, keyPair.publicKey)
            }
            executionTimes[it] = millis.toDouble()
            println("$it:\t${millis / 1000.0} s")
        }
        println("* Testing local Schnorr signature validation: DONE\n")
        printStats(executionTimes)
    }

    // Generate private and public keys
    private fun generateKeyPair(): KeyPair {
        val privateKey = BigInteger(p.bitLength() - 1, random) // Private key x
        val publicKey = g.modPow(privateKey, p)                        // Public key y = g^x mod p
        return KeyPair(privateKey, publicKey)
    }

    // Hash function using SHA-256
    private fun hash(message: String, r: BigInteger): BigInteger {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(message.toByteArray())
        md.update(r.toByteArray())
        return BigInteger(1, md.digest())
    }

    // Sign the message
    private fun sign(message: String, privateKey: BigInteger): Signature {
        val k = BigInteger(p.bitLength() - 1, random)                      // Random k
        val r = g.modPow(k, p)                                                     // r = g^k mod p
        val e = hash(message, r)                                                   // e = H(m || r)
        val s = k.subtract(privateKey.multiply(e)).mod(p.subtract(BigInteger.ONE)) // s = (k - x * e) mod (p-1)
        return Signature(s, e)
    }

    // Verify the signature
    private fun verify(message: String, signature: Signature, publicKey: BigInteger): Boolean {
        val s = signature.s
        val e = signature.e
        val rPrime = (g.modPow(s, p).multiply(publicKey.modPow(e, p))).mod(p) // r’ = g^s * y^e mod p
        val ePrime = hash(message, rPrime)                                    // e’ = H(m || r’)
        return e == ePrime
    }
}

fun main(args: Array<String>) {
    require(args.size == 2) { "Missing arguments: hsm.signatures.schnorr.LocalSchnorrKt <operation> <number of reps>" }
    val operation = args[0]
    val times = args[1].toInt()

    val schnorr = LocalSchnorr()
    when (operation) {
        "sign" -> schnorr.testSignature(times)
        "valSign" -> schnorr.testSignatureValidation(times)
    }
}