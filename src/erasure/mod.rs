//! Reed-Solomon Erasure Coding Implementation
//! 
//! Provides fault-tolerant storage through Reed-Solomon erasure coding with:
//! - Galois field arithmetic operations
//! - Data encoding into multiple shards
//! - Missing shard reconstruction
//! - Data integrity verification

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Galois field for Reed-Solomon operations
#[derive(Debug, Clone)]
pub struct GaloisField {
    /// Field size (must be power of 2)
    size: usize,
    /// Primitive polynomial
    primitive_poly: u32,
    /// Logarithm table
    log_table: Vec<u8>,
    /// Exponential table
    exp_table: Vec<u8>,
}

/// Reed-Solomon erasure coding system
#[derive(Debug)]
pub struct ErasureCoding {
    /// Galois field for operations
    field: GaloisField,
    /// Number of data shards
    data_shards: usize,
    /// Number of parity shards
    parity_shards: usize,
    /// Total number of shards
    total_shards: usize,
    /// Vandermonde matrix for encoding
    encoding_matrix: Vec<Vec<u8>>,
}

/// Encoded data shards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedShards {
    /// Data shards
    pub data_shards: Vec<Vec<u8>>,
    /// Parity shards
    pub parity_shards: Vec<Vec<u8>>,
    /// Shard size
    pub shard_size: usize,
    /// Original data size
    pub original_size: usize,
}

/// Shard reconstruction information
#[derive(Debug, Clone)]
pub struct ReconstructionInfo {
    /// Available shard indices
    pub available_shards: Vec<usize>,
    /// Missing shard indices
    pub missing_shards: Vec<usize>,
    /// Whether reconstruction is possible
    pub can_reconstruct: bool,
}

impl GaloisField {
    /// Create new Galois field GF(2^8)
    pub fn new() -> Self {
        let size = 256;
        let primitive_poly = 0x11D; // x^8 + x^4 + x^3 + x^2 + 1

        let mut log_table = vec![0u8; size];
        let mut exp_table = vec![0u8; size * 2];

        // Build logarithm and exponential tables
        let mut x = 1;
        for i in 0..255 {
            exp_table[i] = x as u8;
            exp_table[i + 255] = x as u8;
            log_table[x] = i as u8;
            
            x = x << 1;
            if x & 0x100 != 0 {
                x ^= primitive_poly;
            }
        }

        Self {
            size,
            primitive_poly: primitive_poly as u32,
            log_table,
            exp_table,
        }
    }

    /// Multiply two elements in the field
    pub fn multiply(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }

        let log_a = self.log_table[a as usize] as usize;
        let log_b = self.log_table[b as usize] as usize;
        self.exp_table[log_a + log_b]
    }

    /// Divide two elements in the field
    pub fn divide(&self, a: u8, b: u8) -> Result<u8> {
        if b == 0 {
            return Err(anyhow!("Division by zero in Galois field"));
        }
        if a == 0 {
            return Ok(0);
        }

        let log_a = self.log_table[a as usize] as usize;
        let log_b = self.log_table[b as usize] as usize;
        let log_result = (log_a + 255 - log_b) % 255;
        Ok(self.exp_table[log_result])
    }

    /// Calculate power of an element
    pub fn power(&self, base: u8, exp: u8) -> u8 {
        if base == 0 {
            return 0;
        }
        if exp == 0 {
            return 1;
        }

        let log_base = self.log_table[base as usize] as usize;
        let log_result = (log_base * exp as usize) % 255;
        self.exp_table[log_result]
    }

    /// Find multiplicative inverse
    pub fn inverse(&self, a: u8) -> Result<u8> {
        if a == 0 {
            return Err(anyhow!("Cannot find inverse of zero"));
        }

        let log_a = self.log_table[a as usize] as usize;
        let log_result = (255 - log_a) % 255;
        Ok(self.exp_table[log_result])
    }

    /// Add two elements (XOR in GF(2^n))
    pub fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// Subtract two elements (XOR in GF(2^n))
    pub fn subtract(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }
}

impl ErasureCoding {
    /// Create new Reed-Solomon encoder/decoder
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        if data_shards == 0 || parity_shards == 0 {
            return Err(anyhow!("Data and parity shards must be greater than 0"));
        }

        if data_shards + parity_shards > 255 {
            return Err(anyhow!("Total shards cannot exceed 255"));
        }

        let field = GaloisField::new();
        let total_shards = data_shards + parity_shards;

        // Build Vandermonde matrix for encoding
        let encoding_matrix = Self::build_vandermonde_matrix(&field, data_shards, total_shards)?;

        Ok(Self {
            field,
            data_shards,
            parity_shards,
            total_shards,
            encoding_matrix,
        })
    }

    /// Encode data into shards
    pub fn encode(&self, data: &[u8]) -> Result<EncodedShards> {
        if data.is_empty() {
            return Err(anyhow!("Cannot encode empty data"));
        }

        let shard_size = (data.len() + self.data_shards - 1) / self.data_shards;
        let padded_size = shard_size * self.data_shards;

        // Pad data to multiple of shard size
        let mut padded_data = data.to_vec();
        padded_data.resize(padded_size, 0);

        // Split data into shards
        let mut data_shards = Vec::new();
        for i in 0..self.data_shards {
            let start = i * shard_size;
            let end = start + shard_size;
            data_shards.push(padded_data[start..end].to_vec());
        }

        // Calculate parity shards
        let mut parity_shards = vec![vec![0u8; shard_size]; self.parity_shards];

        for parity_idx in 0..self.parity_shards {
            let matrix_row = &self.encoding_matrix[self.data_shards + parity_idx];
            
            for data_idx in 0..self.data_shards {
                let coefficient = matrix_row[data_idx];
                
                for byte_idx in 0..shard_size {
                    let product = self.field.multiply(coefficient, data_shards[data_idx][byte_idx]);
                    parity_shards[parity_idx][byte_idx] = self.field.add(
                        parity_shards[parity_idx][byte_idx],
                        product,
                    );
                }
            }
        }

        Ok(EncodedShards {
            data_shards,
            parity_shards,
            shard_size,
            original_size: data.len(),
        })
    }

    /// Decode data from available shards
    pub fn decode(&self, shards: &EncodedShards, available_indices: &[usize]) -> Result<Vec<u8>> {
        if available_indices.len() < self.data_shards {
            return Err(anyhow!("Insufficient shards for reconstruction"));
        }

        let shard_size = shards.shard_size;
        let mut all_shards = Vec::new();

        // Combine data and parity shards
        all_shards.extend(shards.data_shards.clone());
        all_shards.extend(shards.parity_shards.clone());

        // Select available shards for reconstruction
        let mut reconstruction_shards = Vec::new();
        let mut reconstruction_matrix = Vec::new();

        for &idx in available_indices.iter().take(self.data_shards) {
            if idx < all_shards.len() {
                reconstruction_shards.push(all_shards[idx].clone());
                reconstruction_matrix.push(self.encoding_matrix[idx].clone());
            }
        }

        if reconstruction_shards.len() < self.data_shards {
            return Err(anyhow!("Not enough valid shards"));
        }

        // Invert the reconstruction matrix
        let inverted_matrix = self.invert_matrix(&reconstruction_matrix)?;

        // Reconstruct data shards
        let mut reconstructed_data = vec![vec![0u8; shard_size]; self.data_shards];

        for data_idx in 0..self.data_shards {
            for shard_idx in 0..self.data_shards {
                let coefficient = inverted_matrix[data_idx][shard_idx];
                
                for byte_idx in 0..shard_size {
                    let product = self.field.multiply(coefficient, reconstruction_shards[shard_idx][byte_idx]);
                    reconstructed_data[data_idx][byte_idx] = self.field.add(
                        reconstructed_data[data_idx][byte_idx],
                        product,
                    );
                }
            }
        }

        // Combine reconstructed data shards
        let mut result = Vec::new();
        for shard in reconstructed_data {
            result.extend(shard);
        }

        // Trim to original size
        result.truncate(shards.original_size);
        Ok(result)
    }

    /// Check if data can be reconstructed from available shards
    pub fn can_reconstruct(&self, available_shards: &[usize]) -> bool {
        available_shards.len() >= self.data_shards
    }

    /// Get reconstruction information
    pub fn get_reconstruction_info(&self, available_shards: &[usize]) -> ReconstructionInfo {
        let mut missing_shards = Vec::new();
        let available_set = available_shards.iter().collect::<std::collections::HashSet<_>>();

        for i in 0..self.total_shards {
            if !available_set.contains(&i) {
                missing_shards.push(i);
            }
        }

        ReconstructionInfo {
            available_shards: available_shards.to_vec(),
            missing_shards,
            can_reconstruct: self.can_reconstruct(available_shards),
        }
    }

    /// Verify data integrity
    pub fn verify_integrity(&self, original_data: &[u8], shards: &EncodedShards) -> Result<bool> {
        // Re-encode the original data
        let re_encoded = self.encode(original_data)?;

        // Compare all shards
        if re_encoded.data_shards.len() != shards.data_shards.len() {
            return Ok(false);
        }

        if re_encoded.parity_shards.len() != shards.parity_shards.len() {
            return Ok(false);
        }

        for (original, current) in re_encoded.data_shards.iter().zip(&shards.data_shards) {
            if original != current {
                return Ok(false);
            }
        }

        for (original, current) in re_encoded.parity_shards.iter().zip(&shards.parity_shards) {
            if original != current {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Build Vandermonde matrix for encoding
    fn build_vandermonde_matrix(field: &GaloisField, data_shards: usize, total_shards: usize) -> Result<Vec<Vec<u8>>> {
        let mut matrix = vec![vec![0u8; data_shards]; total_shards];

        // Identity matrix for data shards
        for i in 0..data_shards {
            matrix[i][i] = 1;
        }

        // Vandermonde matrix for parity shards
        for i in data_shards..total_shards {
            for j in 0..data_shards {
                matrix[i][j] = field.power((i - data_shards + 1) as u8, j as u8);
            }
        }

        Ok(matrix)
    }

    /// Invert a matrix in the Galois field
    fn invert_matrix(&self, matrix: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        let size = matrix.len();
        if size != matrix[0].len() {
            return Err(anyhow!("Matrix must be square"));
        }

        // Create augmented matrix [A|I]
        let mut augmented = vec![vec![0u8; 2 * size]; size];
        
        for i in 0..size {
            for j in 0..size {
                augmented[i][j] = matrix[i][j];
                augmented[i][j + size] = if i == j { 1 } else { 0 };
            }
        }

        // Gaussian elimination
        for i in 0..size {
            // Find pivot
            let mut pivot_row = i;
            for k in i + 1..size {
                if augmented[k][i] != 0 {
                    pivot_row = k;
                    break;
                }
            }

            if augmented[pivot_row][i] == 0 {
                return Err(anyhow!("Matrix is not invertible"));
            }

            // Swap rows if needed
            if pivot_row != i {
                augmented.swap(i, pivot_row);
            }

            // Scale pivot row
            let pivot = augmented[i][i];
            let inv_pivot = self.field.inverse(pivot)?;
            
            for j in 0..2 * size {
                augmented[i][j] = self.field.multiply(augmented[i][j], inv_pivot);
            }

            // Eliminate column
            for k in 0..size {
                if k != i && augmented[k][i] != 0 {
                    let factor = augmented[k][i];
                    for j in 0..2 * size {
                        let product = self.field.multiply(factor, augmented[i][j]);
                        augmented[k][j] = self.field.subtract(augmented[k][j], product);
                    }
                }
            }
        }

        // Extract inverse matrix
        let mut inverse = vec![vec![0u8; size]; size];
        for i in 0..size {
            for j in 0..size {
                inverse[i][j] = augmented[i][j + size];
            }
        }

        Ok(inverse)
    }

    /// Get configuration
    pub fn get_config(&self) -> (usize, usize) {
        (self.data_shards, self.parity_shards)
    }
}

impl Default for ErasureCoding {
    fn default() -> Self {
        Self::new(4, 2).expect("Default erasure coding configuration should be valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_galois_field_operations() {
        let field = GaloisField::new();
        
        // Test multiplication
        assert_eq!(field.multiply(3, 5), 15);
        assert_eq!(field.multiply(0, 5), 0);
        
        // Test division
        assert_eq!(field.divide(15, 3).unwrap(), 5);
        assert_eq!(field.divide(0, 5).unwrap(), 0);
        
        // Test inverse
        let a = 7;
        let inv_a = field.inverse(a).unwrap();
        assert_eq!(field.multiply(a, inv_a), 1);
    }

    #[test]
    fn test_erasure_coding_encode_decode() {
        let ec = ErasureCoding::new(3, 2).unwrap();
        let data = b"Hello, Reed-Solomon!";

        // Encode
        let shards = ec.encode(data).unwrap();
        assert_eq!(shards.data_shards.len(), 3);
        assert_eq!(shards.parity_shards.len(), 2);

        // Decode with all shards
        let all_indices = vec![0, 1, 2, 3, 4];
        let decoded = ec.decode(&shards, &all_indices).unwrap();
        assert_eq!(decoded, data);

        // Decode with missing data shard
        let partial_indices = vec![0, 1, 3, 4]; // Missing data shard 2
        let decoded_partial = ec.decode(&shards, &partial_indices).unwrap();
        assert_eq!(decoded_partial, data);
    }

    #[test]
    fn test_erasure_coding_reconstruction_info() {
        let ec = ErasureCoding::new(4, 2).unwrap();
        
        let available = vec![0, 1, 2, 3];
        let info = ec.get_reconstruction_info(&available);
        assert!(info.can_reconstruct);
        assert_eq!(info.missing_shards, vec![4, 5]);

        let insufficient = vec![0, 1, 2];
        let info_insufficient = ec.get_reconstruction_info(&insufficient);
        assert!(!info_insufficient.can_reconstruct);
    }

    #[test]
    fn test_integrity_verification() {
        let ec = ErasureCoding::new(3, 2).unwrap();
        let data = b"Test data for integrity check";

        let shards = ec.encode(data).unwrap();
        assert!(ec.verify_integrity(data, &shards).unwrap());

        // Corrupt a shard
        let mut corrupted_shards = shards.clone();
        corrupted_shards.data_shards[0][0] ^= 1; // Flip a bit
        assert!(!ec.verify_integrity(data, &corrupted_shards).unwrap());
    }
}
