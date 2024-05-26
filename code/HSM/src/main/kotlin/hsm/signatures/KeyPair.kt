package hsm.signatures

class KeyPair(val privateKey: ByteArray, val publicKey: ByteArray) {
    override fun toString(): String {
        return "Private key:\n${privateKey.contentToString()}\n" +
                "Public key:\n${publicKey.contentToString()}"
    }
}