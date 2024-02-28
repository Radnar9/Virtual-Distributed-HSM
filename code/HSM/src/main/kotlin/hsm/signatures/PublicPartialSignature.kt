package hsm.signatures

import org.bouncycastle.math.ec.ECPoint
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import java.io.ObjectInput
import java.io.ObjectOutput

class PublicPartialSignature(
    private val signingKeyCommitment: EllipticCurveCommitment,
    private val randomKeyCommitment: EllipticCurveCommitment,
    private val randomPublicKey: ECPoint
) {
    fun getSigningKeyCommitment() = signingKeyCommitment

    fun getRandomKeyCommitment() = randomKeyCommitment

    fun getRandomPublicKey() = randomPublicKey

    fun serialize(out: ObjectOutput) {
        signingKeyCommitment.writeExternal(out)
        randomKeyCommitment.writeExternal(out)
        val encoded = randomPublicKey.getEncoded(true)
        out.writeInt(encoded.size)
        out.write(encoded)
    }

    companion object {
        fun deserialize(schnorrSignatureScheme: SchnorrSignatureScheme, `in`: ObjectInput): PublicPartialSignature {
            val signingKeyCommitment = EllipticCurveCommitment(schnorrSignatureScheme.getCurve())
            signingKeyCommitment.readExternal(`in`)

            val randomKeyCommitment = EllipticCurveCommitment(schnorrSignatureScheme.getCurve())
            randomKeyCommitment.readExternal(`in`)

            val encoded = ByteArray(`in`.readInt())
            `in`.readFully(encoded)

            val randomPublicKey: ECPoint = schnorrSignatureScheme.decodePublicKey(encoded)
            return PublicPartialSignature(signingKeyCommitment, randomKeyCommitment, randomPublicKey)
        }
    }
}