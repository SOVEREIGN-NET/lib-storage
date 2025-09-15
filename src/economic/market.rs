//! Storage Market and Discovery System
//! 
//! Implements a decentralized marketplace for storage services including:
//! - Provider discovery and matching
//! - Service advertising and bidding
//! - Market-making and liquidity provision
//! - Geographic and performance-based routing
//! - Load balancing and capacity management

use crate::types::*;
use crate::economic::pricing::*;
use crate::economic::reputation::*;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Storage marketplace for provider discovery and matching
#[derive(Debug)]
pub struct StorageMarket {
    /// Available storage providers
    providers: HashMap<String, StorageProvider>,
    /// Storage requests awaiting fulfillment
    pending_requests: HashMap<String, StorageRequest>,
    /// Active service advertisements
    service_ads: HashMap<String, ServiceAdvertisement>,
    /// Market statistics
    market_stats: MarketStatistics,
    /// Geographic regions
    regions: HashMap<String, RegionInfo>,
}

/// Market manager (alias for StorageMarket)
pub type MarketManager = StorageMarket;

/// Storage provider information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProvider {
    /// Provider identifier
    pub provider_id: String,
    /// Provider metadata
    pub metadata: ProviderMetadata,
    /// Available storage capacity
    pub capacity: StorageCapacity,
    /// Service capabilities
    pub capabilities: ServiceCapabilities,
    /// Pricing information
    pub pricing: ProviderPricing,
    /// Geographic location
    pub location: GeographicLocation,
    /// Reputation score
    pub reputation_score: f64,
    /// Current availability
    pub availability: ProviderAvailability,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Whether the provider is currently online
    pub is_online: bool,
}

/// Provider metadata and contact information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    /// Provider name
    pub name: String,
    /// Provider description
    pub description: String,
    /// Contact information
    pub contact_info: ContactInfo,
    /// Provider website
    pub website: Option<String>,
    /// Supported protocols
    pub protocols: Vec<String>,
    /// Provider tags/categories
    pub tags: Vec<String>,
}

/// Contact information for providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    /// Email address
    pub email: Option<String>,
    /// Support channels
    pub support_channels: Vec<String>,
    /// API endpoints
    pub api_endpoints: Vec<String>,
}

/// Storage capacity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCapacity {
    /// Total storage capacity (bytes)
    pub total_capacity: u64,
    /// Currently used capacity (bytes)
    pub used_capacity: u64,
    /// Available capacity (bytes)
    pub available_capacity: u64,
    /// Reserved capacity (bytes)
    pub reserved_capacity: u64,
    /// Capacity by storage tier
    pub tier_capacity: HashMap<StorageTier, u64>,
}

/// Service capabilities of a provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCapabilities {
    /// Supported storage tiers
    pub supported_tiers: Vec<StorageTier>,
    /// Maximum file size supported
    pub max_file_size: u64,
    /// Supported replication factors
    pub replication_factors: Vec<u8>,
    /// Encryption capabilities
    pub encryption_support: Vec<EncryptionLevel>,
    /// Erasure coding support
    pub erasure_coding_support: bool,
    /// Backup and archival support
    pub backup_support: bool,
    /// CDN capabilities
    pub cdn_support: bool,
}

/// Provider pricing structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderPricing {
    /// Base pricing per tier
    pub tier_pricing: HashMap<StorageTier, u64>,
    /// Bandwidth pricing
    pub bandwidth_pricing: BandwidthPricing,
    /// Operation pricing
    pub operation_pricing: OperationPricing,
    /// Discount for long-term contracts
    pub volume_discounts: Vec<VolumeDiscount>,
    /// Pricing validity period
    pub pricing_valid_until: u64,
}

/// Bandwidth pricing structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthPricing {
    /// Upload cost per GB
    pub upload_cost_per_gb: u64,
    /// Download cost per GB
    pub download_cost_per_gb: u64,
    /// Free bandwidth allowance
    pub free_bandwidth_gb: u64,
}

/// Operation pricing structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationPricing {
    /// Cost per read operation
    pub read_operation_cost: u64,
    /// Cost per write operation
    pub write_operation_cost: u64,
    /// Cost per delete operation
    pub delete_operation_cost: u64,
    /// Cost per list operation
    pub list_operation_cost: u64,
}

/// Volume discount structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeDiscount {
    /// Minimum storage size for discount
    pub min_storage_size: u64,
    /// Minimum contract duration for discount
    pub min_contract_duration: u64,
    /// Discount percentage
    pub discount_percentage: f64,
}

/// Geographic location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicLocation {
    /// Country code
    pub country: String,
    /// Region/state
    pub region: String,
    /// City
    pub city: String,
    /// Data center location
    pub datacenter: Option<String>,
    /// Coordinates
    pub coordinates: Option<Coordinates>,
}

/// Geographic coordinates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coordinates {
    pub latitude: f64,
    pub longitude: f64,
}

/// Provider availability status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderAvailability {
    /// Overall availability status
    pub status: AvailabilityStatus,
    /// Current load percentage
    pub current_load: f64,
    /// Response time to new requests
    pub response_time: u64,
    /// Maintenance windows
    pub maintenance_windows: Vec<MaintenanceWindow>,
}

/// Provider availability status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AvailabilityStatus {
    Online,
    Busy,
    Maintenance,
    Offline,
    Limited,
}

/// Scheduled maintenance window
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceWindow {
    /// Start time
    pub start_time: u64,
    /// End time
    pub end_time: u64,
    /// Maintenance description
    pub description: String,
    /// Impact level
    pub impact: MaintenanceImpact,
}

/// Maintenance impact levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaintenanceImpact {
    None,        // No service impact
    Low,         // Minimal service impact
    Medium,      // Some service degradation
    High,        // Significant service impact
    Complete,    // Complete service outage
}

/// Service advertisement by providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAdvertisement {
    /// Advertisement ID
    pub ad_id: String,
    /// Provider ID
    pub provider_id: String,
    /// Advertised services
    pub services: Vec<ServiceOffering>,
    /// Special offers
    pub special_offers: Vec<SpecialOffer>,
    /// Advertisement validity
    pub valid_until: u64,
    /// Target customer segments
    pub target_segments: Vec<CustomerSegment>,
}

/// Individual service offering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceOffering {
    /// Service name
    pub name: String,
    /// Service description
    pub description: String,
    /// Storage tier
    pub tier: StorageTier,
    /// Minimum capacity
    pub min_capacity: u64,
    /// Maximum capacity
    pub max_capacity: u64,
    /// Price per GB per month
    pub price_per_gb_month: u64,
    /// SLA guarantees
    pub sla_guarantees: ServiceSLA,
}

/// Service Level Agreement for offerings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSLA {
    /// Uptime guarantee
    pub uptime_guarantee: f64,
    /// Response time guarantee
    pub response_time_ms: u64,
    /// Data durability guarantee
    pub durability_guarantee: f64,
    /// Support response time
    pub support_response_hours: u64,
}

/// Special promotional offers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialOffer {
    /// Offer name
    pub name: String,
    /// Offer description
    pub description: String,
    /// Discount percentage
    pub discount_percentage: f64,
    /// Offer conditions
    pub conditions: Vec<String>,
    /// Offer expiry
    pub expires_at: u64,
    /// Maximum usage
    pub max_usage_count: Option<u32>,
}

/// Customer segments for targeted advertising
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CustomerSegment {
    Individual,
    SmallBusiness,
    Enterprise,
    Developer,
    Archival,
    HighPerformance,
    BudgetConsious,
}

/// Market statistics and analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketStatistics {
    /// Total number of providers
    pub total_providers: u32,
    /// Total available capacity
    pub total_capacity: u64,
    /// Total utilized capacity
    pub utilized_capacity: u64,
    /// Average price per GB
    pub avg_price_per_gb: u64,
    /// Number of active contracts
    pub active_contracts: u32,
    /// Market trends
    pub trends: MarketTrends,
    /// Last updated
    pub last_updated: u64,
}

/// Market trend information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketTrends {
    /// Price trend direction
    pub price_trend: TrendDirection,
    /// Capacity trend direction
    pub capacity_trend: TrendDirection,
    /// Demand trend direction
    pub demand_trend: TrendDirection,
    /// Quality trend direction
    pub quality_trend: TrendDirection,
}

/// Trend direction indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrendDirection {
    Increasing,
    Stable,
    Decreasing,
}

/// Regional market information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionInfo {
    /// Region identifier
    pub region_id: String,
    /// Region name
    pub region_name: String,
    /// Countries in region
    pub countries: Vec<String>,
    /// Provider count in region
    pub provider_count: u32,
    /// Average pricing in region
    pub avg_pricing: u64,
    /// Data residency requirements
    pub data_residency_rules: Vec<String>,
}

/// Provider matching criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchingCriteria {
    /// Required storage capacity
    pub required_capacity: u64,
    /// Preferred storage tier
    pub preferred_tier: StorageTier,
    /// Maximum price per GB
    pub max_price_per_gb: Option<u64>,
    /// Geographic preferences
    pub geographic_preferences: Vec<String>,
    /// Minimum reputation score
    pub min_reputation: Option<f64>,
    /// Required SLA levels
    pub required_sla: Option<ServiceSLA>,
    /// Required capabilities
    pub required_capabilities: Vec<String>,
}

/// Provider search results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSearchResult {
    /// Matching providers
    pub providers: Vec<ProviderMatch>,
    /// Total matches found
    pub total_matches: u32,
    /// Search query used
    pub search_criteria: MatchingCriteria,
    /// Search timestamp
    pub search_timestamp: u64,
}

/// Individual provider match with score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMatch {
    /// Provider information
    pub provider: StorageProvider,
    /// Match score (0.0-1.0)
    pub match_score: f64,
    /// Estimated cost for request
    pub estimated_cost: u64,
    /// Why this provider matches
    pub match_reasons: Vec<String>,
    /// Potential concerns
    pub concerns: Vec<String>,
}

impl StorageMarket {
    /// Create a new storage market
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            pending_requests: HashMap::new(),
            service_ads: HashMap::new(),
            market_stats: MarketStatistics {
                total_providers: 0,
                total_capacity: 0,
                utilized_capacity: 0,
                avg_price_per_gb: 0,
                active_contracts: 0,
                trends: MarketTrends {
                    price_trend: TrendDirection::Stable,
                    capacity_trend: TrendDirection::Stable,
                    demand_trend: TrendDirection::Stable,
                    quality_trend: TrendDirection::Stable,
                },
                last_updated: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            regions: HashMap::new(),
        }
    }

    /// Register a new storage provider
    pub fn register_provider(&mut self, provider: StorageProvider) -> Result<()> {
        self.providers.insert(provider.provider_id.clone(), provider);
        self.update_market_stats();
        Ok(())
    }

    /// Update provider information
    pub fn update_provider(&mut self, provider_id: &str, updates: ProviderUpdate) -> Result<()> {
        let provider = self.providers.get_mut(provider_id)
            .ok_or_else(|| anyhow!("Provider not found"))?;

        match updates {
            ProviderUpdate::Capacity(capacity) => {
                provider.capacity = capacity;
            }
            ProviderUpdate::Pricing(pricing) => {
                provider.pricing = pricing;
            }
            ProviderUpdate::Availability(availability) => {
                provider.availability = availability;
            }
            ProviderUpdate::Reputation(score) => {
                provider.reputation_score = score;
            }
        }

        provider.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.update_market_stats();
        Ok(())
    }

    /// Search for providers based on criteria
    pub fn search_providers(&self, criteria: MatchingCriteria) -> Result<ProviderSearchResult> {
        let mut matches = Vec::new();

        for provider in self.providers.values() {
            if let Some(provider_match) = self.evaluate_provider_match(provider, &criteria) {
                matches.push(provider_match);
            }
        }

        // Sort by match score descending
        matches.sort_by(|a, b| b.match_score.partial_cmp(&a.match_score).unwrap());

        Ok(ProviderSearchResult {
            total_matches: matches.len() as u32,
            providers: matches,
            search_criteria: criteria,
            search_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Evaluate how well a provider matches criteria
    fn evaluate_provider_match(&self, provider: &StorageProvider, criteria: &MatchingCriteria) -> Option<ProviderMatch> {
        let mut score: f64 = 0.0;
        let mut reasons = Vec::new();
        let mut concerns = Vec::new();

        // Check availability
        if provider.availability.status != AvailabilityStatus::Online {
            concerns.push("Provider not currently online".to_string());
            return None; // Skip offline providers
        }

        // Check capacity
        if provider.capacity.available_capacity >= criteria.required_capacity {
            score += 0.3;
            reasons.push("Sufficient capacity available".to_string());
        } else {
            concerns.push("Insufficient available capacity".to_string());
            return None;
        }

        // Check tier support
        if provider.capabilities.supported_tiers.contains(&criteria.preferred_tier) {
            score += 0.2;
            reasons.push(format!("Supports {} tier", format!("{:?}", criteria.preferred_tier)));
        }

        // Check pricing
        if let Some(max_price) = criteria.max_price_per_gb {
            if let Some(tier_price) = provider.pricing.tier_pricing.get(&criteria.preferred_tier) {
                if *tier_price <= max_price {
                    score += 0.2;
                    reasons.push("Price within budget".to_string());
                } else {
                    concerns.push("Price exceeds budget".to_string());
                    score -= 0.1;
                }
            }
        }

        // Check reputation
        if let Some(min_reputation) = criteria.min_reputation {
            if provider.reputation_score >= min_reputation {
                score += 0.2;
                reasons.push("Meets reputation requirements".to_string());
            } else {
                concerns.push("Reputation below minimum".to_string());
                return None;
            }
        }

        // Check geographic preferences
        if !criteria.geographic_preferences.is_empty() {
            for pref in &criteria.geographic_preferences {
                if provider.location.country == *pref || provider.location.region == *pref {
                    score += 0.1;
                    reasons.push(format!("Located in preferred region: {}", pref));
                    break;
                }
            }
        }

        // Estimate cost
        let estimated_cost = self.estimate_cost(provider, criteria);

        Some(ProviderMatch {
            provider: provider.clone(),
            match_score: score.min(1.0),
            estimated_cost,
            match_reasons: reasons,
            concerns,
        })
    }

    /// Estimate cost for a storage request with a provider
    fn estimate_cost(&self, provider: &StorageProvider, criteria: &MatchingCriteria) -> u64 {
        let tier_price = provider.pricing.tier_pricing.get(&criteria.preferred_tier)
            .copied()
            .unwrap_or(100);

        let size_gb = (criteria.required_capacity as f64 / (1024.0 * 1024.0 * 1024.0)).ceil() as u64;
        tier_price * size_gb
    }

    /// Get market statistics
    pub fn get_market_stats(&self) -> &MarketStatistics {
        &self.market_stats
    }

    /// Get providers in a specific region
    pub fn get_providers_by_region(&self, region: &str) -> Vec<&StorageProvider> {
        self.providers.values()
            .filter(|p| p.location.region == region || p.location.country == region)
            .collect()
    }

    /// Get top providers by reputation
    pub fn get_top_providers(&self, limit: usize) -> Vec<&StorageProvider> {
        let mut providers: Vec<_> = self.providers.values().collect();
        providers.sort_by(|a, b| b.reputation_score.partial_cmp(&a.reputation_score).unwrap());
        providers.into_iter().take(limit).collect()
    }

    /// Find storage providers matching requirements
    pub fn find_storage_providers(
        &self,
        required_size: u64,
        min_replicas: u32,
        region_preference: Option<String>,
    ) -> Vec<String> {
        self.providers
            .iter()
            .filter(|(_, provider)| {
                provider.capacity.available_capacity >= required_size
                    && provider.is_online
                    && (region_preference.is_none() 
                        || region_preference.as_ref() == Some(&provider.location.region))
            })
            .take(min_replicas as usize)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Record contract creation for market statistics
    pub async fn record_contract_creation(&mut self, _contract_id: String, _total_cost: u64) -> Result<()> {
        // Update market statistics
        self.update_market_stats();
        Ok(())
    }

    /// Update market statistics
    fn update_market_stats(&mut self) {
        self.market_stats.total_providers = self.providers.len() as u32;
        self.market_stats.total_capacity = self.providers.values()
            .map(|p| p.capacity.total_capacity)
            .sum();
        self.market_stats.utilized_capacity = self.providers.values()
            .map(|p| p.capacity.used_capacity)
            .sum();

        // Calculate average price (simplified)
        let total_prices: u64 = self.providers.values()
            .filter_map(|p| p.pricing.tier_pricing.get(&StorageTier::Cold))
            .sum();
        
        if self.market_stats.total_providers > 0 {
            self.market_stats.avg_price_per_gb = total_prices / (self.market_stats.total_providers as u64);
        }

        self.market_stats.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Provider update types
#[derive(Debug, Clone)]
pub enum ProviderUpdate {
    Capacity(StorageCapacity),
    Pricing(ProviderPricing),
    Availability(ProviderAvailability),
    Reputation(f64),
}

impl Default for StorageMarket {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_market_creation() {
        let market = StorageMarket::new();
        assert_eq!(market.providers.len(), 0);
        assert_eq!(market.market_stats.total_providers, 0);
    }

    #[test]
    fn test_provider_registration() {
        let mut market = StorageMarket::new();
        
        let provider = create_test_provider();
        market.register_provider(provider).unwrap();
        
        assert_eq!(market.providers.len(), 1);
        assert_eq!(market.market_stats.total_providers, 1);
    }

    fn create_test_provider() -> StorageProvider {
        let mut tier_capacity = HashMap::new();
        tier_capacity.insert(StorageTier::Cold, 1024 * 1024 * 1024 * 100); // 100 GB

        let mut tier_pricing = HashMap::new();
        tier_pricing.insert(StorageTier::Cold, 100);

        StorageProvider {
            provider_id: "provider1".to_string(),
            metadata: ProviderMetadata {
                name: "Test Provider".to_string(),
                description: "A test storage provider".to_string(),
                contact_info: ContactInfo {
                    email: Some("test@provider.com".to_string()),
                    support_channels: vec!["email".to_string()],
                    api_endpoints: vec!["https://api.provider.com".to_string()],
                },
                website: Some("https://provider.com".to_string()),
                protocols: vec!["HTTPS".to_string()],
                tags: vec!["reliable".to_string()],
            },
            capacity: StorageCapacity {
                total_capacity: 1024 * 1024 * 1024 * 1000, // 1 TB
                used_capacity: 1024 * 1024 * 1024 * 200,   // 200 GB
                available_capacity: 1024 * 1024 * 1024 * 800, // 800 GB
                reserved_capacity: 0,
                tier_capacity,
            },
            capabilities: ServiceCapabilities {
                supported_tiers: vec![StorageTier::Cold, StorageTier::Warm],
                max_file_size: 1024 * 1024 * 1024 * 10, // 10 GB
                replication_factors: vec![3, 5, 7],
                encryption_support: vec![EncryptionLevel::Standard],
                erasure_coding_support: true,
                backup_support: true,
                cdn_support: false,
            },
            pricing: ProviderPricing {
                tier_pricing,
                bandwidth_pricing: BandwidthPricing {
                    upload_cost_per_gb: 10,
                    download_cost_per_gb: 5,
                    free_bandwidth_gb: 10,
                },
                operation_pricing: OperationPricing {
                    read_operation_cost: 1,
                    write_operation_cost: 2,
                    delete_operation_cost: 1,
                    list_operation_cost: 1,
                },
                volume_discounts: Vec::new(),
                pricing_valid_until: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + 86400,
            },
            location: GeographicLocation {
                country: "US".to_string(),
                region: "West".to_string(),
                city: "San Francisco".to_string(),
                datacenter: Some("DC1".to_string()),
                coordinates: Some(Coordinates {
                    latitude: 37.7749,
                    longitude: -122.4194,
                }),
            },
            reputation_score: 0.8,
            availability: ProviderAvailability {
                status: AvailabilityStatus::Online,
                current_load: 0.3,
                response_time: 100,
                maintenance_windows: Vec::new(),
            },
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            is_online: true,
        }
    }
}
