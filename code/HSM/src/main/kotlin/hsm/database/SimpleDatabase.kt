package hsm.database

import java.util.TreeMap

class SimpleDatabase<K, V>: HsmDatabase<K, V> {
    private val map: MutableMap<K, V> = TreeMap()

    override fun add(key: K, value: V): V? {
        if (map.containsKey(key)) return null
        map[key] = value
        return value
    }

    override fun update(key: K, value: V): V? {
        if (map.containsKey(key)) return null
        map[key] = value
        return value
    }

    override fun get(key: K): V? {
        return map[key]
    }

    override fun delete(key: K): V? {
        return map.remove(key)
    }

    override fun containsKey(key: K): Boolean {
        return map.containsKey(key)
    }
}