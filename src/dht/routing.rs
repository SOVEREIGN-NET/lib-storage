//! Kademlia-based DHT Routing
//! 
//! Implements the Kademlia routing algorithm with K-buckets for efficient
//! peer discovery and routing in the DHT network.

use crate::types::dht_types::{DhtNode, KBucket, RoutingEntry};
use crate::types::NodeId;
use anyhow::{Result, anyhow};
use std::time::{SystemTime, UNIX_EPOCH};

/// Kademlia routing table for DHT operations
#[derive(Debug)]
pub struct KademliaRouter {
    /// Local node ID
    local_id: NodeId,
    /// Routing table with 160 K-buckets (for 256-bit node IDs)
    routing_table: Vec<KBucket>,
    /// K-bucket size (standard Kademlia K value)
    k: usize,
}

impl KademliaRouter {
    /// Create a new Kademlia router
    pub fn new(local_id: NodeId, k: usize) -> Self {
        // Initialize routing table with 160 buckets (for 256-bit node IDs)
        let mut routing_table = Vec::with_capacity(160);
        for _ in 0..160 {
            routing_table.push(KBucket {
                k,
                nodes: Vec::new(),
                last_updated: SystemTime::now(),
            });
        }
        
        Self {
            local_id,
            routing_table,
            k,
        }
    }
    
    /// Calculate XOR distance between two node IDs
    pub fn calculate_distance(&self, a: &NodeId, b: &NodeId) -> u32 {
        let a_bytes = a.as_bytes();
        let b_bytes = b.as_bytes();
        
        for i in 0..32 {
            let xor = a_bytes[i] ^ b_bytes[i];
            if xor != 0 {
                return (i as u32 * 8) + (7 - xor.leading_zeros());
            }
        }
        0
    }
    
    /// Get bucket index for a given distance
    fn get_bucket_index(&self, distance: u32) -> usize {
        std::cmp::min(distance as usize, 159)
    }
    
    /// Add a node to the routing table
    pub async fn add_node(&mut self, node: DhtNode) -> Result<()> {
        let distance = self.calculate_distance(&self.local_id, &node.id);
        let bucket_index = self.get_bucket_index(distance);
        
        if let Some(bucket) = self.routing_table.get_mut(bucket_index) {
            // Check if node already exists
            if let Some(pos) = bucket.nodes.iter().position(|entry| entry.node.id == node.id) {
                // Update existing node
                bucket.nodes[pos].node = node.clone();
                bucket.nodes[pos].last_contact = SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_secs();
                bucket.nodes[pos].failed_attempts = 0;
            } else if bucket.nodes.len() < bucket.k {
                // Add new node if bucket not full
                bucket.nodes.push(RoutingEntry {
                    node: node.clone(),
                    distance,
                    last_contact: SystemTime::now()
                        .duration_since(UNIX_EPOCH)?
                        .as_secs(),
                    failed_attempts: 0,
                });
            } else {
                // Bucket full - replace least recently seen node if it's unresponsive
                let lrs_node_id = bucket.nodes.iter()
                    .min_by_key(|entry| entry.last_contact)
                    .map(|entry| entry.node.id.clone());
                
                if let Some(node_id) = lrs_node_id {
                    // In a real implementation, we would ping the node here
                    // For now, we'll replace if failed_attempts > 3
                    if let Some(lrs_entry) = bucket.nodes.iter().find(|e| e.node.id == node_id) {
                        if lrs_entry.failed_attempts > 3 {
                            // Replace unresponsive node within the same bucket reference
                            let lrs_index = bucket.nodes.iter()
                                .position(|entry| entry.node.id == node_id)
                                .unwrap();
                            bucket.nodes[lrs_index] = RoutingEntry {
                                node: node.clone(),
                                distance,
                                last_contact: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)?
                                    .as_secs(),
                                failed_attempts: 0,
                            };
                        }
                    }
                }
            }
            
            bucket.last_updated = SystemTime::now();
        }
        
        Ok(())
    }
    
    /// Find the K closest nodes to a target ID
    pub fn find_closest_nodes(&self, target: &NodeId, count: usize) -> Vec<DhtNode> {
        let mut closest_nodes = Vec::new();
        
        // Collect all nodes from routing table
        for bucket in &self.routing_table {
            for entry in &bucket.nodes {
                closest_nodes.push((entry.node.clone(), self.calculate_distance(target, &entry.node.id)));
            }
        }
        
        // Sort by distance to target
        closest_nodes.sort_by_key(|(_, distance)| *distance);
        
        // Return top K nodes
        closest_nodes.into_iter()
            .take(count)
            .map(|(node, _)| node)
            .collect()
    }
    
    /// Get all nodes in a specific bucket
    pub fn get_bucket_nodes(&self, bucket_index: usize) -> Vec<&DhtNode> {
        if bucket_index < self.routing_table.len() {
            self.routing_table[bucket_index]
                .nodes
                .iter()
                .map(|entry| &entry.node)
                .collect()
        } else {
            Vec::new()
        }
    }
    
    /// Mark a node as failed (increment failed attempts)
    pub fn mark_node_failed(&mut self, node_id: &NodeId) {
        let distance = self.calculate_distance(&self.local_id, node_id);
        let bucket_index = self.get_bucket_index(distance);
        
        if let Some(bucket) = self.routing_table.get_mut(bucket_index) {
            if let Some(entry) = bucket.nodes.iter_mut().find(|e| e.node.id == *node_id) {
                entry.failed_attempts += 1;
            }
        }
    }
    
    /// Mark a node as responsive (reset failed attempts)
    pub fn mark_node_responsive(&mut self, node_id: &NodeId) -> Result<()> {
        let distance = self.calculate_distance(&self.local_id, node_id);
        let bucket_index = self.get_bucket_index(distance);
        
        if let Some(bucket) = self.routing_table.get_mut(bucket_index) {
            if let Some(entry) = bucket.nodes.iter_mut().find(|e| e.node.id == *node_id) {
                entry.failed_attempts = 0;
                entry.last_contact = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            }
        }
        
        Ok(())
    }
    
    /// Remove a node from the routing table
    pub fn remove_node(&mut self, node_id: &NodeId) {
        let distance = self.calculate_distance(&self.local_id, node_id);
        let bucket_index = self.get_bucket_index(distance);
        
        if let Some(bucket) = self.routing_table.get_mut(bucket_index) {
            bucket.nodes.retain(|entry| entry.node.id != *node_id);
        }
    }
    
    /// Get routing table statistics
    pub fn get_stats(&self) -> RoutingStats {
        let total_nodes: usize = self.routing_table.iter().map(|b| b.nodes.len()).sum();
        let non_empty_buckets = self.routing_table.iter().filter(|b| !b.nodes.is_empty()).count();
        
        RoutingStats {
            total_nodes,
            non_empty_buckets,
            total_buckets: self.routing_table.len(),
        }
    }
}

/// Routing table statistics
#[derive(Debug)]
pub struct RoutingStats {
    pub total_nodes: usize,
    pub non_empty_buckets: usize,
    pub total_buckets: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;
    
    #[test]
    fn test_router_creation() {
        let local_id = Hash::from_bytes(&[1u8; 32]);
        let router = KademliaRouter::new(local_id, 20);
        
        assert_eq!(router.routing_table.len(), 160);
        assert_eq!(router.k, 20);
    }
    
    #[test]
    fn test_distance_calculation() {
        let local_id = Hash::from_bytes(&[1u8; 32]);
        let router = KademliaRouter::new(local_id, 20);
        
        let node_a = Hash::from_bytes(&[1u8; 32]);
        let node_b = Hash::from_bytes(&[2u8; 32]);
        
        let distance = router.calculate_distance(&node_a, &node_b);
        assert!(distance > 0);
        
        // Distance to self should be 0
        let self_distance = router.calculate_distance(&node_a, &node_a);
        assert_eq!(self_distance, 0);
    }
    
    #[test]
    fn test_bucket_index() {
        let local_id = Hash::from_bytes(&[1u8; 32]);
        let router = KademliaRouter::new(local_id, 20);
        
        let distance_0 = 0;
        let distance_10 = 10;
        let distance_200 = 200;
        
        assert_eq!(router.get_bucket_index(distance_0), 0);
        assert_eq!(router.get_bucket_index(distance_10), 10);
        assert_eq!(router.get_bucket_index(distance_200), 159); // Capped at 159
    }
    
    #[tokio::test]
    async fn test_add_node() {
        let local_id = Hash::from_bytes(&[1u8; 32]);
        let mut router = KademliaRouter::new(local_id, 20);
        
        let test_node = DhtNode {
            id: Hash::from_bytes(&[2u8; 32]),
            addresses: vec!["127.0.0.1:33442".to_string()],
            public_key: lib_crypto::PostQuantumSignature {
                algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
                signature: vec![],
                public_key: lib_crypto::PublicKey {
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                    ed25519_pk: vec![],
                    key_id: [0u8; 32],
                },
                timestamp: 0,
            },
            last_seen: 0,
            reputation: 1000,
            storage_info: None,
        };
        
        router.add_node(test_node).await.unwrap();
        
        let stats = router.get_stats();
        assert_eq!(stats.total_nodes, 1);
        assert_eq!(stats.non_empty_buckets, 1);
    }
}
