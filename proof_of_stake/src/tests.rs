//! PoS system tests

use std::ops::Range;

use namada_core::ledger::storage::testing::TestWlStorage;
use namada_core::ledger::storage_api::token::credit_tokens;
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
use crate::types::{GenesisValidator, ValidatorState};
use crate::{
    active_validator_set_handle, bond_tokens_new,
    inactive_validator_set_handle, init_genesis_new, staking_token_address,
    unbond_tokens_new, validator_state_handle,
};

proptest! {
    // Generate arb valid input for `test_init_genesis_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_init_genesis(

    pos_params in arb_pos_params(None),
    start_epoch in (0_u64..1000).prop_map(Epoch),
    genesis_validators in arb_genesis_validators(1..200),

    ) {
        test_init_genesis_aux(pos_params, start_epoch, genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_bonds_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_bonds(

    pos_params in arb_pos_params(Some(5)),
    genesis_validators in arb_genesis_validators(1..3),

    ) {
        test_bonds_aux(pos_params, genesis_validators)
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
    s.storage.block.epoch = start_epoch;

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

        let state = validator_state_handle(&validator.address)
            .get(&mut s, start_epoch, &params)
            .unwrap();

        assert_eq!(state, Some(ValidatorState::Candidate));
    }
}

/// Test bonding
fn test_bonds_aux(params: PosParams, mut validators: Vec<GenesisValidator>) {
    println!("Test inputs: {params:?}, genesis validators: {validators:#?}");
    let mut s = TestWlStorage::default();

    let epoch = s.storage.block.epoch;
    init_genesis_new(&mut s, &params, validators.clone().into_iter(), epoch)
        .unwrap();
    s.commit_genesis().unwrap();

    s.storage.block.epoch = s.storage.block.epoch.next();

    let validator = validators.first().unwrap();

    let amount = token::Amount::from(100_500_000);
    credit_tokens(&mut s, &staking_token_address(), &validator.address, amount)
        .unwrap();

    let epoch = s.storage.block.epoch;
    bond_tokens_new(
        &mut s,
        Some(&validator.address),
        &validator.address,
        amount,
        epoch,
    )
    .unwrap();

    s.storage.block.epoch = s.storage.block.epoch.next();

    let epoch = s.storage.block.epoch;
    unbond_tokens_new(
        &mut s,
        Some(&validator.address),
        &validator.address,
        amount,
        epoch,
    )
    .unwrap();
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
