package hsm

enum class Operation {
    GENERATE_SIGNING_KEY,
    SIGN_DATA,
    GET_PUBLIC_KEY,
    GET_RANDOM_NUMBER;

    companion object {
        fun getOperation(ordinal: Int): Operation {
            return Operation.entries[ordinal]
        }
    }
}