package hsm.signatures

enum class SignatureScheme {
    SCHNORR,
    BLS;

    companion object {
        fun getScheme(ordinal: Int): SignatureScheme {
            return SignatureScheme.entries[ordinal]
        }
    }
}