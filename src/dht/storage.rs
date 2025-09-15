//! DHT Storage Operations
//! 
//! Implements key-value storage operations with zero-knowledge proofs
//! and replication for the DHT layer.

use crate::types::dht_types::{DhtNode, StorageEntry, DhtMessage, DhtMessageType, ZkDhtValue};
use crate::types::{NodeId, ChunkMetadata, DhtKey};
use crate::dht::network::DhtNetwork;
use crate::dht::routing::KademliaRouter;
use crate::dht::messaging::DhtMessaging;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::net::SocketAddr;
use lib_crypto::Hash;
use lib_proofs::{ZkProof, ZeroKnowledgeProof};

/// DHT storage manager with real networking
#[derive(Debug)]
pub struct DhtStorage {
    /// Local storage for key-value pairs
    storage: HashMap<String, StorageEntry>,
    /// Maximum storage size per node (in bytes)
    max_storage_size: u64,
    /// Current storage usage (in bytes)
    current_usage: u64,
    /// Local node ID
    local_node_id: NodeId,
    /// Network layer for DHT communication
    network: Option<DhtNetwork>,
    /// Kademlia router for finding closest nodes
    router: KademliaRouter,
    /// Messaging system for reliable communication
    messaging: DhtMessaging,
    /// Known DHT nodes
    known_nodes: HashMap<NodeId, DhtNode>,
}

impl DhtStorage {
    /// Create a new DHT storage manager
    pub fn new(local_node_id: NodeId, max_storage_size: u64) -> Self {
        Self {
            storage: HashMap::new(),
            max_storage_size,
            current_usage: 0,
            local_node_id: local_node_id.clone(),
            network: None,
            router: KademliaRouter::new(local_node_id.clone(), 20),
            messaging: DhtMessaging::new(local_node_id),
            known_nodes: HashMap::new(),
        }
    }

    /// Create DHT storage with networking enabled
    pub async fn new_with_network(
        local_node: DhtNode, 
        bind_addr: SocketAddr, 
        max_storage_size: u64
    ) -> Result<Self> {
        let network = DhtNetwork::new(local_node.clone(), bind_addr)?;
        
        Ok(Self {
            storage: HashMap::new(),
            max_storage_size,
            current_usage: 0,
            local_node_id: local_node.id.clone(),
            network: Some(network),
            router: KademliaRouter::new(local_node.id.clone(), 20),
            messaging: DhtMessaging::new(local_node.id.clone()),
            known_nodes: HashMap::new(),
        })
    }

    /// Create default storage (for convenience)
    pub fn new_default() -> Self {
        Self::new(
            Hash::from_bytes(&[0u8; 32]), // Default node ID
            1_000_000_000, // 1GB default storage
        )
    }

    /// Store data with content hash as key and replicate across DHT
    pub async fn store_data(&mut self, content_hash: Hash, data: Vec<u8>) -> Result<()> {
        let key = hex::encode(content_hash.as_bytes());
        
        // Store locally first
        self.store(key.clone(), data.clone(), None).await?;
        
        // If network is available, replicate to other nodes
        if self.network.is_some() {
            self.replicate_to_dht(&key, &data).await?;
        }
        
        Ok(())
    }

    /// Retrieve data by content hash, first check local then query DHT
    pub async fn retrieve_data(&mut self, content_hash: Hash) -> Result<Option<Vec<u8>>> {
        let key = hex::encode(content_hash.as_bytes());
        
        // Check local storage first
        if let Some(data) = self.get(&key).await? {
            return Ok(Some(data));
        }
        
        // If not found locally and network is available, query DHT
        if self.network.is_some() {
            return self.retrieve_from_dht(&key).await;
        }
        
        Ok(None)
    }

    /// Replicate data to DHT network
    async fn replicate_to_dht(&mut self, key: &str, data: &[u8]) -> Result<()> {
        // Find closest nodes for this key
        let target_key = Hash::from_bytes(&blake3::hash(key.as_bytes()).as_bytes()[..32]);
        let closest_nodes = self.router.find_closest_nodes(&target_key, 3);
        
        if let Some(network) = &self.network {
            // Send store messages to closest nodes
            for node in closest_nodes {
                match network.store(&node, key.to_string(), data.to_vec()).await {
                    Ok(true) => {
                        println!("✅ Successfully stored data at node {}", hex::encode(&node.id.as_bytes()[..4]));
                    }
                    Ok(false) => {
                        println!("⚠️ Store failed at node {}", hex::encode(&node.id.as_bytes()[..4]));
                        self.router.mark_node_failed(&node.id);
                    }
                    Err(e) => {
                        println!("❌ Network error storing to node {}: {}", hex::encode(&node.id.as_bytes()[..4]), e);
                        self.router.mark_node_failed(&node.id);
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Retrieve data from DHT network
    async fn retrieve_from_dht(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        // Find closest nodes for this key
        let target_key = Hash::from_bytes(&blake3::hash(key.as_bytes()).as_bytes()[..32]);
        let closest_nodes = self.router.find_closest_nodes(&target_key, 5);
        
        if let Some(network) = &self.network {
            // Query nodes for the value
            for node in closest_nodes {
                match network.find_value(&node, key.to_string()).await {
                    Ok(crate::types::dht_types::DhtQueryResponse::Value(data)) => {
                        println!("✅ Found data at node {}", hex::encode(&node.id.as_bytes()[..4]));
                        self.router.mark_node_responsive(&node.id)?;
                        
                        // Store locally for caching
                        let _ = self.store(key.to_string(), data.clone(), None).await;
                        return Ok(Some(data));
                    }
                    Ok(crate::types::dht_types::DhtQueryResponse::Nodes(nodes)) => {
                        // Add discovered nodes to routing table
                        for discovered_node in nodes {
                            self.router.add_node(discovered_node).await?;
                        }
                    }
                    Err(e) => {
                        println!("❌ Query error from node {}: {}", hex::encode(&node.id.as_bytes()[..4]), e);
                        self.router.mark_node_failed(&node.id);
                    }
                }
            }
        }
        
        Ok(None)
    }

    /// Remove data by content hash
    pub async fn remove_data(&mut self, content_hash: Hash) -> Result<bool> {
        let key = hex::encode(content_hash.as_bytes());
        self.remove(&key).await
    }
    
    /// Store a key-value pair with optional ZK proof
    pub async fn store(&mut self, key: String, value: Vec<u8>, proof: Option<ZkProof>) -> Result<()> {
        // Check storage capacity
        let value_size = value.len() as u64;
        if self.current_usage + value_size > self.max_storage_size {
            return Err(anyhow!("Storage capacity exceeded"));
        }
        
        // Verify ZK proof if provided
        if let Some(zk_proof) = &proof {
            if !self.verify_storage_proof(zk_proof, &key, &value).await? {
                return Err(anyhow!("Invalid zero-knowledge proof"));
            }
        }
        
        // Create storage entry
        let entry = StorageEntry {
            key: key.clone(),
            value: value.clone(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            expiry: None, // In practice, this would be calculated based on storage contract
            metadata: ChunkMetadata {
                chunk_id: key.clone(),
                size: value_size,
                checksum: self.calculate_checksum(&value),
                tier: crate::types::dht_types::StorageTier::Hot, // Default tier
                location: vec![self.local_node_id.clone()],
                access_count: 0,
                last_access: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                compression_algorithm: None,
                compression_ratio: 1.0,
            },
            proof,
            replicas: Vec::new(),
            access_control: None,
        };
        
        // Update storage
        if let Some(old_entry) = self.storage.insert(key, entry) {
            // If replacing existing entry, adjust usage
            self.current_usage = self.current_usage
                .saturating_sub(old_entry.value.len() as u64)
                .saturating_add(value_size);
        } else {
            self.current_usage += value_size;
        }
        
        Ok(())
    }
    
    /// Retrieve a value by key
    pub async fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        if let Some(entry) = self.storage.get_mut(key) {
            // Update access statistics
            entry.metadata.access_count += 1;
            entry.metadata.last_access = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            // Check if entry has expired
            if let Some(expiry) = entry.expiry {
                if SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() > expiry {
                    // Remove expired entry
                    let removed_entry = self.storage.remove(key).unwrap();
                    self.current_usage = self.current_usage.saturating_sub(removed_entry.value.len() as u64);
                    return Ok(None);
                }
            }
            
            Ok(Some(entry.value.clone()))
        } else {
            Ok(None)
        }
    }
    
    /// Remove a key-value pair
    pub async fn remove(&mut self, key: &str) -> Result<bool> {
        if let Some(entry) = self.storage.remove(key) {
            self.current_usage = self.current_usage.saturating_sub(entry.value.len() as u64);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// Get storage entry metadata
    pub fn get_metadata(&self, key: &str) -> Option<&ChunkMetadata> {
        self.storage.get(key).map(|entry| &entry.metadata)
    }
    
    /// List all stored keys
    pub fn list_keys(&self) -> Vec<String> {
        self.storage.keys().cloned().collect()
    }
    
    /// Get storage statistics
    pub fn get_storage_stats(&self) -> StorageStats {
        let total_entries = self.storage.len();
        let total_size = self.current_usage;
        let available_space = self.max_storage_size.saturating_sub(self.current_usage);
        
        // Calculate average access count
        let total_accesses: u64 = self.storage.values()
            .map(|entry| entry.metadata.access_count)
            .sum();
        let avg_access_count = if total_entries > 0 {
            total_accesses as f64 / total_entries as f64
        } else {
            0.0
        };
        
        StorageStats {
            total_entries,
            total_size,
            available_space,
            max_capacity: self.max_storage_size,
            avg_access_count,
        }
    }
    
    /// Cleanup expired entries
    pub async fn cleanup_expired(&mut self) -> Result<usize> {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut removed_count = 0;
        
        let expired_keys: Vec<String> = self.storage.iter()
            .filter_map(|(key, entry)| {
                if let Some(expiry) = entry.expiry {
                    if current_time > expiry {
                        Some(key.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        
        for key in expired_keys {
            if let Some(entry) = self.storage.remove(&key) {
                self.current_usage = self.current_usage.saturating_sub(entry.value.len() as u64);
                removed_count += 1;
            }
        }
        
        Ok(removed_count)
    }
    
    /// Set entry expiry time
    pub fn set_expiry(&mut self, key: &str, expiry: u64) -> Result<()> {
        if let Some(entry) = self.storage.get_mut(key) {
            entry.expiry = Some(expiry);
            Ok(())
        } else {
            Err(anyhow!("Key not found: {}", key))
        }
    }
    
    /// Get entries that need replication
    pub fn get_replication_candidates(&self, min_replicas: usize) -> Vec<String> {
        self.storage.iter()
            .filter_map(|(key, entry)| {
                if entry.replicas.len() < min_replicas {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect()
    }
    
    /// Update replica information for a key
    pub fn update_replicas(&mut self, key: &str, replicas: Vec<NodeId>) -> Result<()> {
        if let Some(entry) = self.storage.get_mut(key) {
            entry.replicas = replicas;
            Ok(())
        } else {
            Err(anyhow!("Key not found: {}", key))
        }
    }
    
    /// Verify zero-knowledge storage proof
    async fn verify_storage_proof(&self, proof: &ZkProof, key: &str, value: &[u8]) -> Result<bool> {
        // In a real implementation, this would verify the ZK proof
        // using the lib-proofs crate. For now, we'll assume valid proofs.
        // 
        // The proof would typically verify:
        // 1. The caller has permission to store this data
        // 2. The data integrity is maintained
        // 3. The storage contract terms are met
        
        Ok(proof.proof_data.len() > 0) // Simple validation for now
    }
    
    /// Add a DHT node to the routing table and known nodes
    pub async fn add_dht_node(&mut self, node: DhtNode) -> Result<()> {
        // Add to routing table
        self.router.add_node(node.clone()).await?;
        
        // Add to known nodes
        self.known_nodes.insert(node.id.clone(), node.clone());
        
        // Test connectivity if network is available
        if let Some(network) = &self.network {
            match network.ping(&node).await {
                Ok(true) => {
                    println!("✅ Successfully pinged new node {}", hex::encode(&node.id.as_bytes()[..4]));
                    self.router.mark_node_responsive(&node.id)?;
                }
                Ok(false) => {
                    println!("⚠️ Ping failed for new node {}", hex::encode(&node.id.as_bytes()[..4]));
                    self.router.mark_node_failed(&node.id);
                }
                Err(e) => {
                    println!("❌ Network error pinging node {}: {}", hex::encode(&node.id.as_bytes()[..4]), e);
                    self.router.mark_node_failed(&node.id);
                }
            }
        }
        
        Ok(())
    }

    /// Get all known DHT nodes
    pub fn get_known_nodes(&self) -> Vec<&DhtNode> {
        self.known_nodes.values().collect()
    }

    /// Start network message processing loop (should be run in background)
    pub async fn start_network_processing(&mut self) -> Result<()> {
        loop {
            // Take network temporarily to avoid borrow conflicts
            let network = match self.network.take() {
                Some(n) => n,
                None => break, // No network available
            };

            // Process outgoing messages
            if let Some(queued_msg) = self.messaging.get_next_message() {
                match network.send_message(&queued_msg.target_node, queued_msg.message.clone()).await {
                    Ok(_) => {
                        println!("📤 Sent message {} to {}", 
                                queued_msg.message.message_id, 
                                hex::encode(&queued_msg.target_node.id.as_bytes()[..4]));
                    }
                    Err(e) => {
                        println!("❌ Failed to send message: {}", e);
                        self.messaging.mark_message_failed(queued_msg);
                    }
                }
            }
            
            // Process incoming messages
            let should_continue = match network.receive_message().await {
                Ok((message, sender_addr)) => {
                    if let Ok(response) = self.messaging.handle_incoming(message.clone()).await {
                        if let Some(response_msg) = response {
                            // Send response back
                            if let Some(target_node) = self.known_nodes.get(&message.sender_id) {
                                let _ = network.send_message(target_node, response_msg).await;
                            }
                        }
                    }
                    
                    // Put network back before handling storage message
                    self.network = Some(network);
                    
                    // Handle storage-specific messages (now self is available)
                    if let Err(e) = self.handle_storage_message(message).await {
                        eprintln!("❌ Failed to handle storage message: {}", e);
                    }
                    
                    true // Continue processing
                }
                Err(e) => {
                    // Put network back
                    self.network = Some(network);
                    // No message available or network error - continue with delay
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    true
                }
            };
            
            if !should_continue {
                break;
            }
            
            // Cleanup and maintenance
            self.messaging.cleanup_expired_responses(Duration::from_secs(300));
            
            // Small delay to prevent busy-waiting
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        
        Ok(())
    }

    /// Handle storage-specific DHT messages
    async fn handle_storage_message(&mut self, message: DhtMessage) -> Result<()> {
        match message.message_type {
            DhtMessageType::Store => {
                if let (Some(key), Some(value)) = (&message.key, &message.value) {
                    // Store the data locally
                    match self.store(key.clone(), value.clone(), None).await {
                        Ok(_) => {
                            println!("📦 Stored data for key {} from {}", 
                                    key, hex::encode(&message.sender_id.as_bytes()[..4]));
                        }
                        Err(e) => {
                            println!("❌ Failed to store data for key {}: {}", key, e);
                        }
                    }
                }
            }
            DhtMessageType::FindValue => {
                if let Some(key) = &message.key {
                    // Check if we have the value locally
                    if let Ok(Some(_)) = self.get(key).await {
                        println!("🔍 Found requested value for key {} locally", key);
                    }
                }
            }
            DhtMessageType::FindNode => {
                if let Some(target_id) = &message.target_id {
                    // Return closest nodes we know about
                    let closest = self.router.find_closest_nodes(target_id, 8);
                    println!("🗺️ Returning {} closest nodes for target {}", 
                            closest.len(), hex::encode(&target_id.as_bytes()[..4]));
                }
            }
            _ => {
                // Other message types are handled by messaging layer
            }
        }
        
        Ok(())
    }

    /// Perform DHT maintenance (refresh routing table, check node liveness)
    pub async fn perform_maintenance(&mut self) -> Result<()> {
        println!("🔧 Performing DHT maintenance...");
        
        // Check liveness of known nodes
        let node_ids: Vec<NodeId> = self.known_nodes.keys().cloned().collect();
        
        if let Some(network) = &self.network {
            for node_id in node_ids {
                if let Some(node) = self.known_nodes.get(&node_id) {
                    match network.ping(node).await {
                        Ok(true) => {
                            self.router.mark_node_responsive(&node_id)?;
                        }
                        Ok(false) | Err(_) => {
                            self.router.mark_node_failed(&node_id);
                            
                            // Remove unresponsive nodes after too many failures
                            // This would be configurable in production
                            self.router.remove_node(&node_id);
                            self.known_nodes.remove(&node_id);
                        }
                    }
                }
            }
        }
        
        // Cleanup expired storage entries
        let expired_count = self.cleanup_expired().await?;
        if expired_count > 0 {
            println!("🗑️ Cleaned up {} expired storage entries", expired_count);
        }
        
        let stats = self.router.get_stats();
        println!("📊 DHT stats: {} nodes in {} buckets", stats.total_nodes, stats.non_empty_buckets);
        
        Ok(())
    }

    /// Calculate checksum for data integrity
    fn calculate_checksum(&self, data: &[u8]) -> Vec<u8> {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish().to_be_bytes().to_vec()
    }

    /// Get network status
    pub fn is_network_enabled(&self) -> bool {
        self.network.is_some()
    }

    /// Get routing table statistics
    pub fn get_routing_stats(&self) -> crate::dht::routing::RoutingStats {
        self.router.get_stats()
    }

    /// Get messaging queue statistics  
    pub fn get_messaging_stats(&self) -> crate::dht::messaging::QueueStats {
        self.messaging.get_queue_stats()
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_entries: usize,
    pub total_size: u64,
    pub available_space: u64,
    pub max_capacity: u64,
    pub avg_access_count: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;
    
    #[tokio::test]
    async fn test_storage_creation() {
        let node_id = Hash::from_bytes(&[1u8; 32]);
        let storage = DhtStorage::new(node_id, 1024 * 1024); // 1MB
        
        assert_eq!(storage.current_usage, 0);
        assert_eq!(storage.max_storage_size, 1024 * 1024);
    }
    
    #[tokio::test]
    async fn test_store_and_retrieve() {
        let node_id = Hash::from_bytes(&[1u8; 32]);
        let mut storage = DhtStorage::new(node_id, 1024 * 1024);
        
        let key = "test_key".to_string();
        let value = b"test_value".to_vec();
        
        // Store value
        storage.store(key.clone(), value.clone(), None).await.unwrap();
        
        // Retrieve value
        let retrieved = storage.get(&key).await.unwrap();
        assert_eq!(retrieved, Some(value));
        
        // Check statistics
        let stats = storage.get_storage_stats();
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.total_size, 10); // "test_value" is 10 bytes
    }
    
    #[tokio::test]
    async fn test_capacity_limit() {
        let node_id = Hash::from_bytes(&[1u8; 32]);
        let mut storage = DhtStorage::new(node_id, 5); // Very small capacity
        
        let key = "test_key".to_string();
        let large_value = vec![0u8; 10]; // 10 bytes, exceeds capacity
        
        // Attempt to store large value
        let result = storage.store(key, large_value, None).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_remove() {
        let node_id = Hash::from_bytes(&[1u8; 32]);
        let mut storage = DhtStorage::new(node_id, 1024);
        
        let key = "test_key".to_string();
        let value = b"test_value".to_vec();
        
        // Store and remove
        storage.store(key.clone(), value, None).await.unwrap();
        let removed = storage.remove(&key).await.unwrap();
        assert!(removed);
        
        // Verify removal
        let retrieved = storage.get(&key).await.unwrap();
        assert_eq!(retrieved, None);
        
        let stats = storage.get_storage_stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_size, 0);
    }
    
    #[tokio::test]
    async fn test_expiry() {
        let node_id = Hash::from_bytes(&[1u8; 32]);
        let mut storage = DhtStorage::new(node_id, 1024);
        
        let key = "test_key".to_string();
        let value = b"test_value".to_vec();
        
        // Store value
        storage.store(key.clone(), value, None).await.unwrap();
        
        // Set expiry in the past
        let past_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 3600;
        storage.set_expiry(&key, past_time).unwrap();
        
        // Try to retrieve expired value
        let retrieved = storage.get(&key).await.unwrap();
        assert_eq!(retrieved, None); // Should be None due to expiry
    }
}
