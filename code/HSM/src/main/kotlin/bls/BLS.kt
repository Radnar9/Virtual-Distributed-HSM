package bls

import hsm.signatures.KeyPair
import java.math.BigInteger


class BLS(threshold: Int) {
    private external fun initialize(threshold: Int)
    private external fun getOrderBytes(): ByteArray
    private external fun computeKeyPair(): Array<ByteArray>
    private external fun computePublicKey(privateKey: ByteArray): ByteArray
    private external fun computeSignature(privateKey: ByteArray, message: ByteArray): ByteArray
    private external fun computeVerification(signature: ByteArray, message: ByteArray, publicKey: ByteArray): Boolean
    private external fun interpolatePartialSignatures(vararg partialSignatures: Array<ByteArray>): ByteArray
    private external fun interpolatePartialPublicKeys(vararg partialPublicKeys: Array<ByteArray>): ByteArray

    private val order: BigInteger
    private val minThreshold = threshold + 2

    init {
        System.loadLibrary("Pairing")
        initialize(threshold)
        this.order = BigInteger(1, getOrderBytes())
    }

    fun getOrder(): BigInteger {
        return order
    }

    fun genKeyPair(): KeyPair {
        val keys = computeKeyPair()
        return KeyPair(keys[0], keys[1])
    }

    fun genKeyPair(privateKey: BigInteger): KeyPair {
        val publicKey = computePublicKey(privateKey.toByteArray())
        return KeyPair(privateKey.toByteArray(), publicKey)
    }

    fun computePublicKey(privateKey: BigInteger): ByteArray {
        return computePublicKey(privateKey.toByteArray())
    }

    fun sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        return computeSignature(privateKey, message)
    }

    fun verify(signature: ByteArray, message: ByteArray, publicKey: ByteArray): Boolean {
        return computeVerification(signature, message, publicKey)
    }

    fun combinePartialSignatures(
        partialSignatures: Map<BigInteger, ByteArray>,
        partialPublicKeys: Map<BigInteger, ByteArray>,
        message: ByteArray,
    ): ByteArray {
        val validPartialSignatures = partialSignatures.filter { partialSignature ->
            verify(partialSignature.value, message, partialPublicKeys[partialSignature.key]!!)
        }
        // TODO: if validPartialSignatures < minThreshold -> return a custom exception like SignatureException
        val serializedPartialSignatures = serializePartialData(validPartialSignatures)
        return interpolatePartialSignatures(*serializedPartialSignatures)
    }

    fun combinePartialPublicKeys(partialPublicKeys: Map<BigInteger, ByteArray>): ByteArray {
        val serializedPartialPublicKeys = serializePartialData(partialPublicKeys)

        return interpolatePartialPublicKeys(*serializedPartialPublicKeys)
    }

    companion object {
        private fun serializePartialData(partialData: Map<BigInteger, ByteArray>): Array<Array<ByteArray>> {
            val serializedPartialData: ArrayList<Array<ByteArray>> = ArrayList(partialData.size)
            var i = 0
            for ((key, value) in partialData) {
                val data = arrayOf<ByteArray>(key.toByteArray(), value)
                serializedPartialData.add(i++, data)
            }
            return serializedPartialData.toTypedArray()
        }
    }
}