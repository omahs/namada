//! PoS system tests

use std::ops::Range;

use namada_core::ledger::storage::testing::TestWlStorage;
use namada_core::ledger::storage_api::token::credit_tokens;
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
use namada_core::types::address::testing::{
    address_from_simple_seed, arb_address, arb_established_address,
};
use namada_core::types::address::Address;
use namada_core::types::key::common::SecretKey;
use namada_core::types::key::testing::{
    arb_common_keypair, common_sk_from_simple_seed,
};
use namada_core::types::storage::Epoch;
use namada_core::types::{address, token};
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
    active_validator_set_handle, become_validator_new, bond_tokens_new,
    copy_validator_sets_and_positions, inactive_validator_set_handle,
    init_genesis_new, read_active_validator_set_addresses_with_stake,
    staking_token_address, unbond_tokens_new, validator_state_handle,
    withdraw_tokens_new,
};

proptest! {
    // Generate arb valid input for `test_init_genesis_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_init_genesis(

    pos_params in arb_pos_params(Some(50)),
    start_epoch in (0_u64..1000).prop_map(Epoch),
    genesis_validators in arb_genesis_validators(1..100),

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

proptest! {
    // Generate arb valid input for `test_become_validator_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_become_validator(

    pos_params in arb_pos_params(Some(5)),
    new_validator in arb_established_address().prop_map(Address::Established),
    new_validator_consensus_key in arb_common_keypair(),
    genesis_validators in arb_genesis_validators(1..3),

    ) {
        test_become_validator_aux(pos_params, new_validator,
            new_validator_consensus_key, genesis_validators)
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
/// NOTE: copy validator sets each time we advance the epoch
fn test_bonds_aux(
    mut params: PosParams,
    mut validators: Vec<GenesisValidator>,
) {
    println!("\nTest inputs: {params:?}, genesis validators: {validators:#?}");
    let mut s = TestWlStorage::default();

    // Genesis
    let mut current_epoch = dbg!(s.storage.block.epoch);
    init_genesis_new(
        &mut s,
        &params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    s.commit_genesis().unwrap();

    // Advance to epoch 1
    current_epoch = advance_epoch(&mut s, &params);

    let validator = validators.first().unwrap();

    // Self-bond
    let amount = token::Amount::from(100_500_000);
    credit_tokens(&mut s, &staking_token_address(), &validator.address, amount)
        .unwrap();
    bond_tokens_new(&mut s, None, &validator.address, amount, current_epoch)
        .unwrap();

    // Advance to epoch 2
    current_epoch = advance_epoch(&mut s, &params);

    // Get a non-validating account with tokens
    let delegator = address::testing::gen_implicit_address();
    let amount = token::Amount::from(201_000_000);
    credit_tokens(&mut s, &staking_token_address(), &delegator, amount)
        .unwrap();
    let balance_key = token::balance_key(&staking_token_address(), &delegator);
    let balance = s
        .read::<token::Amount>(&balance_key)
        .unwrap()
        .unwrap_or_default();
    dbg!(balance);

    // Advance to epoch 3
    current_epoch = advance_epoch(&mut s, &params);

    // Delegation
    bond_tokens_new(
        &mut s,
        Some(&delegator),
        &validator.address,
        amount,
        current_epoch,
    )
    .unwrap();

    // Advance to epoch 5
    for _ in 0..2 {
        current_epoch = advance_epoch(&mut s, &params);
    }

    // Unbond the self-bond
    unbond_tokens_new(&mut s, None, &validator.address, amount, current_epoch)
        .unwrap();

    // Unbond delegation
    unbond_tokens_new(
        &mut s,
        Some(&delegator),
        &validator.address,
        amount,
        current_epoch,
    )
    .unwrap();

    let withdrawable_offset = params.unbonding_len + params.pipeline_len;

    // Advance to withdrawable epoch
    for _ in 0..withdrawable_offset {
        current_epoch = advance_epoch(&mut s, &params);
    }

    for ep in Epoch::default().iter_range(params.unbonding_len * 3) {
        println!("Epoch {ep}");
        let a = read_active_validator_set_addresses_with_stake(
            &s,
            &active_validator_set_handle(),
            ep,
        )
        .unwrap();
        dbg!(a);
    }

    // Withdraw the self-bond
    withdraw_tokens_new(&mut s, None, &validator.address, current_epoch)
        .unwrap();

    // Withdraw the delegation
    withdraw_tokens_new(
        &mut s,
        Some(&delegator),
        &validator.address,
        current_epoch,
    )
    .unwrap();
}

/// Test validator initialization.
fn test_become_validator_aux(
    params: PosParams,
    new_validator: Address,
    new_validator_consensus_key: SecretKey,
    mut validators: Vec<GenesisValidator>,
) {
    println!(
        "Test inputs: {params:?}, new validator: {new_validator}, genesis \
         validators: {validators:#?}"
    );

    let mut s = TestWlStorage::default();

    // Genesis
    let mut current_epoch = dbg!(s.storage.block.epoch);
    init_genesis_new(
        &mut s,
        &params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    s.commit_genesis().unwrap();

    // Advance to epoch 1
    current_epoch = advance_epoch(&mut s, &params);

    // Initialize the validator account
    let consensus_key = new_validator_consensus_key.to_public();
    become_validator_new(
        &mut s,
        &params,
        &new_validator,
        &consensus_key,
        current_epoch,
        Decimal::new(5, 2),
        Decimal::new(5, 2),
    )
    .unwrap();

    // Self-bond to the new validator
    let amount = token::Amount::from(100_500_000);
    credit_tokens(&mut s, &staking_token_address(), &new_validator, amount)
        .unwrap();
    bond_tokens_new(&mut s, None, &new_validator, amount, current_epoch)
        .unwrap();

    // Advance to epoch 2
    current_epoch = advance_epoch(&mut s, &params);

    // Unbond the self-bond
    unbond_tokens_new(&mut s, None, &new_validator, amount, current_epoch)
        .unwrap();

    let withdrawable_offset = params.unbonding_len + params.pipeline_len;

    // Advance to withdrawable epoch
    for _ in 0..withdrawable_offset {
        current_epoch = advance_epoch(&mut s, &params);
    }

    // Withdraw the self-bond
    withdraw_tokens_new(&mut s, None, &new_validator, current_epoch).unwrap();
}

/// Advance to the next epoch. Returns the new epoch.
fn advance_epoch(s: &mut TestWlStorage, params: &PosParams) -> Epoch {
    s.storage.block.epoch = s.storage.block.epoch.next();
    let current_epoch = s.storage.block.epoch;
    copy_validator_sets_and_positions(
        s,
        current_epoch,
        current_epoch + params.pipeline_len,
        &active_validator_set_handle(),
        &inactive_validator_set_handle(),
    )
    .unwrap();
    current_epoch
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
