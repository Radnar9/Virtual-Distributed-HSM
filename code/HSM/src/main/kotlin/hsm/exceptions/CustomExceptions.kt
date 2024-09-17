package hsm.exceptions

class KeyPairNotFoundException(message: String) : Exception(message)

class OperationNotFoundException(message: String) : Exception(message)

class InvalidKeySchemeException(message: String) : Exception(message)