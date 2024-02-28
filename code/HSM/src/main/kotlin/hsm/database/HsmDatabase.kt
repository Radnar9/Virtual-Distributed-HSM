package hsm.database

interface HsmDatabase<K, V> {
    fun add(key: K, value: V): V?
    fun update(key: K, value: V): V?
    fun get(key: K): V?
    fun delete(key: K): V?
    fun containsKey(key: K): Boolean
}