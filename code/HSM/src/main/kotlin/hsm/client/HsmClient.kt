package hsm.client

import hsm.signatures.*
import java.math.BigInteger
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    if (args.isEmpty() || args.size < 2) {
        println("""
            Usage: hsm.client.HsmClientKt    keyGen           <client id> <index key id> <schnorr or bls>
                                             sign             <client id> <index key id> <schnorr or bls> <data>
                                             enc              <client id> <data>
                                             dec              <client id> <ciphertext>
                                             valSign          <client id> <signature> <initial data>
                                             availableKeys    <client id>
                                             help
        """.trimIndent())
        exitProcess(-1)
    }
    val operation = args[0]
    val clientId = args[1].toInt()

    val clientAPI = ClientAPI(clientId)
    when (operation) {
        "keyGen" -> {
            val indexId = args[2]
            val signatureScheme = stringToSignatureScheme(args[3])
            val publicKey = clientAPI.generateKey(indexId, signatureScheme)
            println("$signatureScheme signing public key: ${BigInteger(publicKey).toString(16)}\n")
        }
        "sign" -> {
            val indexId = args[2]
            val signatureScheme = stringToSignatureScheme(args[3])
            val data = args[4].toByteArray()
            val signature = clientAPI.signData(indexId, signatureScheme, data)
            println("$signatureScheme signature: ${BigInteger(signature).toString(16)}\n")
        }
        "enc" -> {
            val data = args[2].toByteArray()
            val ciphertext = clientAPI.encryptData(data)
            println("Encrypted message: ${BigInteger(ciphertext).toString(16)}\n")
        }
        "dec" -> {
            val ciphertext = BigInteger(args[2], 16).toByteArray()
            val plainData = clientAPI.decryptData(ciphertext)
            println("Decrypted message: ${plainData?.decodeToString()}\n")
        }
        "valSign" -> {
            val signature = BigInteger(args[2], 16)
            val initialData = args[3].toByteArray()
            val validity = clientAPI.validateSignature(signature.toByteArray(), initialData)
            println("The signature is ${if (validity) "valid" else "invalid"}.\n")
        }
        "availableKeys" -> clientAPI.availableKeys()
        "help" -> clientAPI.commands()
        else -> println("Operation not found: $operation")
    }

    clientAPI.close()
}
