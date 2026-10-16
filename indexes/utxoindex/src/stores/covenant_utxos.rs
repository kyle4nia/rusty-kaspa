use crate::core::model::{CompactUtxoCollection, CompactUtxoEntry, UtxoSetByCovenantId, UtxoSetByScriptPublicKey};

use kaspa_consensus_core::tx::{TransactionIndexType, TransactionOutpoint};
use kaspa_core::debug;
use kaspa_database::prelude::{CachePolicy, CachedDbAccess, DB, DirectDbWriter, StoreResult};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// Keys:

/// Size of the covenant-id seek bucket (a raw [`Hash`]).
pub const COVENANT_ID_KEY_SIZE: usize = kaspa_hashes::HASH_SIZE;
/// Size of the [`TransactionOutpoint`] suffix: 32 bytes of transaction id + 4 bytes of little-endian index.
pub const TRANSACTION_OUTPOINT_KEY_SIZE: usize = kaspa_hashes::HASH_SIZE + size_of::<TransactionIndexType>();
/// Full access key: covenant id bucket followed by the outpoint suffix.
pub const COVENANT_FULL_ACCESS_KEY_SIZE: usize = COVENANT_ID_KEY_SIZE + TRANSACTION_OUTPOINT_KEY_SIZE;

/// Full [`CompactUtxoEntry`] access key: 32 bytes of covenant-id bucket, then 36 bytes of outpoint.
/// The covenant id is a fixed-width prefix, so a prefix seek over it yields every utxo of that covenant.
#[derive(Eq, Hash, PartialEq, Debug, Clone, Serialize, Deserialize)]
struct CovenantFullAccessKey(Arc<Vec<u8>>);

impl CovenantFullAccessKey {
    fn new(covenant_id: &Hash, outpoint: &TransactionOutpoint) -> Self {
        let mut bytes = Vec::with_capacity(COVENANT_FULL_ACCESS_KEY_SIZE);
        bytes.extend_from_slice(&covenant_id.as_bytes());
        bytes.extend_from_slice(&outpoint.transaction_id.as_bytes());
        bytes.extend_from_slice(&outpoint.index.to_le_bytes());
        Self(Arc::new(bytes))
    }
}

impl AsRef<[u8]> for CovenantFullAccessKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Reconstruct a [`TransactionOutpoint`] from the 36-byte outpoint suffix that a covenant-id prefix
/// seek returns (the covenant-id bucket is stripped by the seek).
fn outpoint_from_suffix(suffix: &[u8]) -> TransactionOutpoint {
    let transaction_id = Hash::from_slice(&suffix[..kaspa_hashes::HASH_SIZE]);
    let index = TransactionIndexType::from_le_bytes(
        <[u8; size_of::<TransactionIndexType>()]>::try_from(&suffix[kaspa_hashes::HASH_SIZE..]).expect("expected index size"),
    );
    TransactionOutpoint::new(transaction_id, index)
}

// Traits:

pub trait UtxoSetByCovenantIdStoreReader {
    /// Get the [`UtxoSetByCovenantId`] set for the queried covenant ids.
    fn get_utxos_from_covenant_ids(&self, covenant_ids: Vec<Hash>) -> StoreResult<UtxoSetByCovenantId>;
}

pub trait UtxoSetByCovenantIdStore: UtxoSetByCovenantIdStoreReader {
    /// Remove the covenant-bearing entries of the given [`UtxoSetByScriptPublicKey`] from the store.
    /// Entries without a covenant id are ignored (they are never written here).
    fn remove_utxo_entries(&mut self, utxo_entries: &UtxoSetByScriptPublicKey) -> StoreResult<()>;

    /// Add the covenant-bearing entries of the given [`UtxoSetByScriptPublicKey`] into the store.
    /// Entries without a covenant id are ignored.
    fn add_utxo_entries(&mut self, utxo_entries: &UtxoSetByScriptPublicKey) -> StoreResult<()>;

    /// Removes all entries in the cache and db, besides the prefix itself.
    fn delete_all(&mut self) -> StoreResult<()>;
}

// Implementation:

#[derive(Clone)]
pub struct DbUtxoSetByCovenantIdStore {
    db: Arc<DB>,
    access: CachedDbAccess<CovenantFullAccessKey, CompactUtxoEntry>,
}

impl DbUtxoSetByCovenantIdStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::UtxoIndexByCovenantId.into()) }
    }
}

impl UtxoSetByCovenantIdStoreReader for DbUtxoSetByCovenantIdStore {
    fn get_utxos_from_covenant_ids(&self, covenant_ids: Vec<Hash>) -> StoreResult<UtxoSetByCovenantId> {
        let covenant_count = covenant_ids.len();
        let mut entries_count: usize = 0;
        let mut utxos_by_covenant_id = UtxoSetByCovenantId::new();
        for covenant_id in covenant_ids.into_iter() {
            let bucket = covenant_id.as_bytes();
            let inner = CompactUtxoCollection::from_iter(
                self.access.seek_iterator(Some(&bucket[..]), None, usize::MAX, false).map(|res| {
                    let (key, entry) = res.unwrap();
                    (outpoint_from_suffix(&key[..]), entry)
                }),
            );
            entries_count += inner.len();
            utxos_by_covenant_id.insert(covenant_id, inner);
        }
        debug!("IDXPRC, Executed a query for the utxo set of {} covenant ids yielding {} entries", covenant_count, entries_count);
        Ok(utxos_by_covenant_id)
    }
}

impl UtxoSetByCovenantIdStore for DbUtxoSetByCovenantIdStore {
    fn remove_utxo_entries(&mut self, utxo_entries: &UtxoSetByScriptPublicKey) -> StoreResult<()> {
        if utxo_entries.is_empty() {
            return Ok(());
        }

        let mut writer = DirectDbWriter::new(&self.db);

        let mut to_remove = utxo_entries.values().flat_map(|compact_utxo_collection| {
            compact_utxo_collection
                .iter()
                .filter_map(|(transaction_outpoint, compact_utxo)| {
                    compact_utxo.covenant_id.map(|covenant_id| CovenantFullAccessKey::new(&covenant_id, transaction_outpoint))
                })
        });

        self.access.delete_many(&mut writer, &mut to_remove)?;

        Ok(())
    }

    fn add_utxo_entries(&mut self, utxo_entries: &UtxoSetByScriptPublicKey) -> StoreResult<()> {
        if utxo_entries.is_empty() {
            return Ok(());
        }

        let mut writer = DirectDbWriter::new(&self.db);

        let mut to_add = utxo_entries.values().flat_map(|compact_utxo_collection| {
            compact_utxo_collection.iter().filter_map(|(transaction_outpoint, compact_utxo)| {
                compact_utxo.covenant_id.map(|covenant_id| (CovenantFullAccessKey::new(&covenant_id, transaction_outpoint), *compact_utxo))
            })
        });

        self.access.write_many(&mut writer, &mut to_add)?;

        Ok(())
    }

    fn delete_all(&mut self) -> StoreResult<()> {
        self.access.delete_all(DirectDbWriter::new(&self.db))
    }
}
