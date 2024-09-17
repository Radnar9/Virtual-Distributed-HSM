package hsm.signatures

import java.security.InvalidParameterException

enum class KeyScheme {
    SCHNORR,
    BLS,
    SYMMETRIC;

    companion object {
        fun getScheme(ordinal: Int): KeyScheme {
            return KeyScheme.entries[ordinal]
        }
    }
}

fun stringToSignatureScheme(signatureSchemeStr: String): KeyScheme {
    return when (signatureSchemeStr) {
        "schnorr" -> KeyScheme.SCHNORR
        "bls" -> KeyScheme.BLS
        "symmetric" -> KeyScheme.SYMMETRIC
        else ->  throw InvalidParameterException("Invalid key scheme")
    }
}
