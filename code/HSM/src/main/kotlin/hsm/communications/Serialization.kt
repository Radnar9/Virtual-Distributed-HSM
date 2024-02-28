package hsm.communications

import java.io.ObjectInput
import java.io.ObjectOutput

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
