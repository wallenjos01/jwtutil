package org.wallentines.jwt;

import org.wallentines.mdcfg.ConfigSection;

import java.util.HashMap;
import java.util.Map;

public interface KeyStore {

    <T> T getKey(String name, KeyType<T> type);

    <T> void setKey(String name, KeyType<T> type, T key);

    <T> void clearKey(String name, KeyType<T> type);


    default KeySupplier supplier() {
        return new KeySupplier() {
            @Override
            public <T> T getKey(ConfigSection joseHeader, KeyType<T> type) {
                if(!joseHeader.hasString("kid")) return null;
                return KeyStore.this.getKey(joseHeader.getString("kid"), type);
            }
        };
    }

    default KeySupplier supplier(String name) {
        return new KeySupplier() {
            @Override
            public <T> T getKey(ConfigSection joseHeader, KeyType<T> type) {
                return KeyStore.this.getKey(name, type);
            }
        };
    }

    default <K> KeySupplier supplier(KeyType<K> requiredType) {
        return new KeySupplier() {
            @Override
            public <T> T getKey(ConfigSection joseHeader, KeyType<T> type) {
                if(requiredType != type || !joseHeader.hasString("kid")) return null;
                return KeyStore.this.getKey(joseHeader.getString("kid"), type);
            }
        };
    }

    default <K> KeySupplier supplier(String name, KeyType<K> requiredType) {
        return new KeySupplier() {
            @Override
            public <T> T getKey(ConfigSection joseHeader, KeyType<T> type) {
                if(requiredType != type) return null;
                return KeyStore.this.getKey(name, type);
            }
        };
    }

    class KeyRegistry<T> {
        private final KeyType<T> type;
        private final Map<String, T> keys = new HashMap<>();

        public KeyRegistry(KeyType<T> type) {
            this.type = type;
        }
        KeyType<T> getType() {
            return type;
        }
        boolean hasKey(String key) {
            return keys.containsKey(key);
        }
        T getKey(String key) {
            return keys.get(key);
        }
        void setKey(String name, T key) {
            this.keys.put(name, key);
        }
        T clearKey(String name) {
            return this.keys.remove(name);
        }

    }

}
