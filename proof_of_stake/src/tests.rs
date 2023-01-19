//! PoS system tests

use std::ops::Range;

use namada_core::ledger::storage::testing::TestWlStorage;
use namada_core::types::address::testing::address_from_simple_seed;
use namada_core::types::key::testing::common_sk_from_simple_seed;
use namada_core::types::storage::Epoch;
use namada_core::types::token;
use proptest::prelude::*;
use proptest::test_runner::Config;
use rust_decimal::Decimal;
// Use `RUST_LOG=info` (or another tracing level) and `--nocapture` to see
// `tracing` logs from tests
use test_log::test;

use crate::parameters::testing::arb_pos_params;
use crate::parameters::PosParams;
use crate::types::GenesisValidator;
use crate::{
    active_validator_set_handle, inactive_validator_set_handle,
    init_genesis_new,
};

proptest! {
    // Generate arb valid input for `test_init_genesis_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_init_genesis(

    pos_params in arb_pos_params(),
    start_epoch in (0_u64..1000).prop_map(Epoch),
    genesis_validators in arb_genesis_validators(1..200),

    ) {
        test_init_genesis_aux(pos_params, start_epoch, genesis_validators)
    }
}

/// Test genesis initialization
fn test_init_genesis_aux(
    params: PosParams,
    start_epoch: Epoch,
    mut validators: Vec<GenesisValidator>,
) {
    println!(
        "Test inputs: {params:?}, {start_epoch}, genesis validators: \
         {validators:#?}"
    );
    let mut s = TestWlStorage::default();

    init_genesis_new(
        &mut s,
        &params,
        validators.clone().into_iter(),
        start_epoch,
    )
    .unwrap();

    validators.sort_by(|a, b| a.tokens.cmp(&b.tokens));
    for (i, validator) in validators.into_iter().rev().enumerate() {
        println!("Validator {validator:?}");

        if (i as u64) < params.max_validator_slots {
            // should be in active set
            let handle = active_validator_set_handle().at(&start_epoch);
            assert!(handle.at(&validator.tokens).iter(&s).unwrap().any(
                |result| {
                    let (_pos, addr) = result.unwrap();
                    addr == validator.address
                }
            ));
        } else {
            // TODO: one more set once we have `below_threshold`

            // should be in inactive set
            let handle = inactive_validator_set_handle().at(&start_epoch);
            assert!(handle.at(&validator.tokens.into()).iter(&s).unwrap().any(
                |result| {
                    let (_pos, addr) = result.unwrap();
                    addr == validator.address
                }
            ));
        }
    }
}

fn arb_genesis_validators(
    size: Range<usize>,
) -> impl Strategy<Value = Vec<GenesisValidator>> {
    let tokens: Vec<_> = (0..size.end)
        .map(|_| (1..=1_000_000_000_000_u64).prop_map(token::Amount::from))
        .collect();
    (size, tokens).prop_map(|(size, token_amounts)| {
        // use unique seeds to generate validators' address and consensus key
        let seeds = (0_u64..).take(size);
        seeds
            .zip(token_amounts)
            .map(|(seed, tokens)| {
                let address = address_from_simple_seed(seed);
                let consensus_sk = common_sk_from_simple_seed(seed);
                let consensus_key = consensus_sk.to_public();

                let commission_rate = Decimal::new(005, 2);
                let max_commission_rate_change = Decimal::new(0001, 3);
                GenesisValidator {
                    address,
                    tokens,
                    consensus_key,
                    commission_rate,
                    max_commission_rate_change,
                }
            })
            .collect()
    })
}
