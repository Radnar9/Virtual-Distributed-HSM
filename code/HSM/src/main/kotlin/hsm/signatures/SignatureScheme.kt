package hsm.signatures

import java.security.InvalidParameterException

enum class SignatureScheme {
    SCHNORR,
    BLS;

    companion object {
        fun getScheme(ordinal: Int): SignatureScheme {
            return SignatureScheme.entries[ordinal]
        }
    }
}

fun stringToSignatureScheme(signatureSchemeStr: String): SignatureScheme {
    return when (signatureSchemeStr) {
        "schnorr" -> SignatureScheme.SCHNORR
        "bls" -> SignatureScheme.BLS
        else ->  throw InvalidParameterException("Invalid signature scheme")
    }
}
