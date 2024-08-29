package hsm.communications

import java.io.ObjectInput
import java.io.ObjectOutput
import java.math.BigInteger

fun writeByteArray(out: ObjectOutput, bytes: ByteArray?) {
    out.writeInt(bytes?.size ?: -1)
    if (bytes != null) out.write(bytes)
}

fun readByteArray(`in`: ObjectInput): ByteArray {
    val len = `in`.readInt()
    if (len == -1) return ByteArray(0)

    val result = ByteArray(len)
    `in`.readFully(result)
    return result
}

fun serializeBigInteger(value: BigInteger, out: ObjectOutput) {
    val b = value.toByteArray()
    out.writeInt(b.size)
    out.write(b)
}

fun deserializeBigInteger(`in`: ObjectInput): BigInteger {
    val len = `in`.readInt()
    val b = ByteArray(len)
    `in`.readFully(b)
    return BigInteger(b)
}

fun ByteArray.joinByteArray(bytesToJoin: ByteArray): ByteArray {
    val finalByteArray = ByteArray(this.size + bytesToJoin.size)
    System.arraycopy(this, 0, finalByteArray, 0, this.size)
    System.arraycopy(bytesToJoin, 0, finalByteArray, this.size, bytesToJoin.size)
    return finalByteArray
}

fun Byte.joinByteArray(bytesToJoin: ByteArray): ByteArray {
    val finalByteArray = ByteArray(1 + bytesToJoin.size)
    finalByteArray[0] = this
    System.arraycopy(bytesToJoin, 0, finalByteArray, 1, bytesToJoin.size)
    return finalByteArray
}
