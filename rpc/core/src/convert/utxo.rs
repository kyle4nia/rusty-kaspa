//! Conversion functions for UTXO related types.

use crate::RpcUtxoEntry;
use crate::RpcUtxosByAddressesEntry;
use crate::RpcUtxosByCovenantIdEntry;
use kaspa_addresses::Prefix;
use kaspa_index_core::indexed_utxos::{UtxoSetByCovenantId, UtxoSetByScriptPublicKey};
use kaspa_txscript::extract_script_pub_key_address;

// ----------------------------------------------------------------------------
// index to rpc_core
// ----------------------------------------------------------------------------

pub fn utxo_set_into_rpc(item: &UtxoSetByScriptPublicKey, prefix: Option<Prefix>) -> Vec<RpcUtxosByAddressesEntry> {
    item.iter()
        .flat_map(|(script_public_key, utxo_collection)| {
            let address = prefix.and_then(|x| extract_script_pub_key_address(script_public_key, x).ok());
            utxo_collection
                .iter()
                .map(|(outpoint, entry)| RpcUtxosByAddressesEntry {
                    address: address.clone(),
                    outpoint: (*outpoint).into(),
                    utxo_entry: RpcUtxoEntry::new(
                        entry.amount,
                        script_public_key.clone(),
                        entry.block_daa_score,
                        entry.is_coinbase,
                        entry.covenant_id,
                    ),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

pub fn covenant_utxo_set_into_rpc(item: &UtxoSetByCovenantId) -> Vec<RpcUtxosByCovenantIdEntry> {
    item.iter()
        .flat_map(|(covenant_id, utxo_collection)| {
            utxo_collection
                .iter()
                .map(|(outpoint, entry)| RpcUtxosByCovenantIdEntry {
                    covenant_id: *covenant_id,
                    outpoint: (*outpoint).into(),
                    utxo_entry: RpcUtxoEntry::new(
                        entry.amount,
                        entry.script_public_key.clone(),
                        entry.block_daa_score,
                        entry.is_coinbase,
                        Some(*covenant_id),
                    ),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}
