package hsm.signatures.bls

import hsm.client.printStats
import java.math.BigInteger
import kotlin.system.measureTimeMillis

class LocalBls {
    // KeyPair class to hold private and public keys
    private data class KeyPair(val privateKey: BigInteger, val publicKey: BigInteger)

    private val blsScheme = BlsSignatureScheme(0)

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
        println("* Testing local BLS signature: STARTING")
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
        println("* Testing local BLS signature: DONE\n")
        printStats(executionTimes)
    }

    fun testSignatureValidation(times: Int) {
        println("* Testing local BLS signature validation: STARTING")
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
        println("* Testing local BLS signature validation: DONE\n")
        printStats(executionTimes)
    }

    private fun generateKeyPair(): KeyPair {
        val keyPair = blsScheme.genKeyPair()
        return KeyPair(BigInteger(keyPair.privateKey), BigInteger(keyPair.publicKey))
    }

    private fun sign(message: String, privateKey: BigInteger): ByteArray {
        return blsScheme.sign(privateKey.toByteArray(), message.toByteArray())
    }

    private fun verify(message: String, signature: ByteArray, publicKey: BigInteger): Boolean {
        return blsScheme.verifySignature(signature, message.toByteArray(), publicKey.toByteArray())
    }
}

fun main(args: Array<String>) {
    require(args.size == 2) { "Missing arguments: hsm.signatures.bls.LocalBlsKt <operation> <number of reps>" }
    val operation = args[0]
    val times = args[1].toInt()

    val bls = LocalBls()
    when (operation) {
        "sign" -> bls.testSignature(times)
        "valSign" -> bls.testSignatureValidation(times)
    }
}