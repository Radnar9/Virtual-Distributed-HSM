package hsm.signatures

import hsm.communications.readByteArray
import hsm.communications.writeByteArray
import org.bouncycastle.math.ec.ECPoint
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import java.io.ObjectInput
import java.io.ObjectOutput

class SchnorrPublicPartialSignature(
    private val signingKeyCommitment: EllipticCurveCommitment,
    private val randomKeyCommitment: EllipticCurveCommitment,
    private val randomPublicKey: ECPoint,
    private val signingPublicKey: ByteArray,
) {
    fun getSigningKeyCommitment() = signingKeyCommitment

    fun getRandomKeyCommitment() = randomKeyCommitment

    fun getRandomPublicKey() = randomPublicKey
    fun getSigningPublicKey() = signingPublicKey

    fun serialize(out: ObjectOutput) {
        signingKeyCommitment.writeExternal(out)
        randomKeyCommitment.writeExternal(out)
        val encoded = randomPublicKey.getEncoded(true)
        writeByteArray(out, encoded)
        writeByteArray(out, signingPublicKey)
    }

    companion object {
        fun deserialize(schnorrSignatureScheme: SchnorrSignatureScheme, `in`: ObjectInput): SchnorrPublicPartialSignature {
            val signingKeyCommitment = EllipticCurveCommitment(schnorrSignatureScheme.getCurve())
            signingKeyCommitment.readExternal(`in`)

            val randomKeyCommitment = EllipticCurveCommitment(schnorrSignatureScheme.getCurve())
            randomKeyCommitment.readExternal(`in`)

            val encoded = ByteArray(`in`.readInt())
            `in`.readFully(encoded)
            val randomPublicKey: ECPoint = schnorrSignatureScheme.decodePublicKey(encoded)

            val signingPublicKeyDecoded = readByteArray(`in`)
            return SchnorrPublicPartialSignature(signingKeyCommitment, randomKeyCommitment, randomPublicKey, signingPublicKeyDecoded)
        }
    }
}