//! PoS system tests

use std::cmp::min;
use std::ops::Range;

use namada_core::ledger::storage::testing::TestWlStorage;
use namada_core::ledger::storage_api::collections::lazy_map::{
    self, NestedSubKey,
};
use namada_core::ledger::storage_api::token::credit_tokens;
use namada_core::ledger::storage_api::StorageRead;
use namada_core::types::address::testing::{
    address_from_simple_seed, arb_established_address,
};
use namada_core::types::address::{Address, EstablishedAddressGen};
use namada_core::types::key::common::SecretKey;
use namada_core::types::key::testing::{
    arb_common_keypair, common_sk_from_simple_seed,
};
use namada_core::types::storage::Epoch;
use namada_core::types::{address, key, token};
use proptest::prelude::*;
use proptest::test_runner::Config;
use rust_decimal::Decimal;
// Use `RUST_LOG=info` (or another tracing level) and `--nocapture` to see
// `tracing` logs from tests
use test_log::test;

use crate::parameters::testing::arb_pos_params;
use crate::parameters::PosParams;
use crate::types::{
    GenesisValidator, Position, ReverseOrdTokenAmount, ValidatorState,
    WeightedValidatorNew,
};
use crate::{
    active_validator_set_handle, become_validator_new, bond_handle,
    bond_tokens_new, copy_validator_sets_and_positions,
    find_validator_by_raw_hash, inactive_validator_set_handle,
    init_genesis_new, insert_validator_into_set,
    insert_validator_into_validator_set,
    read_active_validator_set_addresses_with_stake,
    read_inactive_validator_set_addresses_with_stake,
    read_num_active_validators, read_total_stake, read_validator_delta_value,
    read_validator_stake, staking_token_address, total_deltas_handle,
    unbond_handle, unbond_tokens_new, validator_state_handle,
    withdraw_tokens_new, write_validator_address_raw_hash,
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
    // This can be useful for debugging:
    // params.pipeline_len = 2;
    // params.unbonding_len = 4;
    println!("\nTest inputs: {params:?}, genesis validators: {validators:#?}");
    let mut s = TestWlStorage::default();

    // Genesis
    let mut current_epoch = s.storage.block.epoch;
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

    // Read some data before submitting bond
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let pos_balance_pre = s
        .read::<token::Amount>(&token::balance_key(
            &staking_token_address(),
            &super::ADDRESS,
        ))
        .unwrap()
        .unwrap_or_default();
    let total_stake_before =
        read_total_stake(&s, &params, pipeline_epoch).unwrap();

    // Self-bond
    let amount = token::Amount::from(100_500_000);
    credit_tokens(&mut s, &staking_token_address(), &validator.address, amount)
        .unwrap();
    bond_tokens_new(&mut s, None, &validator.address, amount, current_epoch)
        .unwrap();

    // Check the bond delta
    let self_bond = bond_handle(&validator.address, &validator.address);
    let delta = self_bond
        .get_delta_val(&s, pipeline_epoch, &params)
        .unwrap();
    assert_eq!(delta, Some(amount.change()));

    // Check the validator in the validator set
    let set =
        read_active_validator_set_addresses_with_stake(&s, pipeline_epoch)
            .unwrap();
    assert!(set.into_iter().any(
        |WeightedValidatorNew {
             bonded_stake,
             address,
         }| {
            address == validator.address
                && bonded_stake == validator.tokens + amount
        }
    ));

    let val_deltas = read_validator_delta_value(
        &s,
        &params,
        &validator.address,
        pipeline_epoch,
    )
    .unwrap();
    assert_eq!(val_deltas, Some(amount.change()));

    let total_deltas_handle = total_deltas_handle();
    assert_eq!(
        current_epoch,
        total_deltas_handle.get_last_update(&s).unwrap().unwrap()
    );
    let total_stake_after =
        read_total_stake(&s, &params, pipeline_epoch).unwrap();
    assert_eq!(total_stake_before + amount, total_stake_after);

    // Advance to epoch 2
    let self_bond_epoch = current_epoch.clone();
    current_epoch = advance_epoch(&mut s, &params);

    // Get a non-validating account with tokens
    let delegator = address::testing::gen_implicit_address();
    let amount_del = token::Amount::from(201_000_000);
    credit_tokens(&mut s, &staking_token_address(), &delegator, amount_del)
        .unwrap();
    let balance_key = token::balance_key(&staking_token_address(), &delegator);
    let balance = s
        .read::<token::Amount>(&balance_key)
        .unwrap()
        .unwrap_or_default();
    assert_eq!(balance, amount_del);

    // Advance to epoch 3
    current_epoch = advance_epoch(&mut s, &params);
    let delegation_epoch = current_epoch.clone();

    // Delegation
    bond_tokens_new(
        &mut s,
        Some(&delegator),
        &validator.address,
        amount_del,
        current_epoch,
    )
    .unwrap();
    let val_stake_pre = read_validator_stake(
        &s,
        &params,
        &validator.address,
        current_epoch + params.pipeline_len - 1,
    )
    .unwrap()
    .unwrap_or_default();
    let val_stake_post = read_validator_stake(
        &s,
        &params,
        &validator.address,
        current_epoch + params.pipeline_len,
    )
    .unwrap()
    .unwrap_or_default();
    assert_eq!(validator.tokens + amount, val_stake_pre);
    assert_eq!(validator.tokens + amount + amount_del, val_stake_post);
    let delegation = bond_handle(&delegator, &validator.address);
    assert_eq!(
        delegation
            .get_sum(&s, current_epoch + params.pipeline_len - 1, &params)
            .unwrap()
            .unwrap_or_default(),
        token::Change::default()
    );
    assert_eq!(
        delegation
            .get_sum(&s, current_epoch + params.pipeline_len, &params)
            .unwrap()
            .unwrap_or_default(),
        amount_del.change()
    );

    // Advance to epoch 5
    for _ in 0..2 {
        current_epoch = advance_epoch(&mut s, &params);
    }
    let unbond_epoch = current_epoch.clone();

    // Unbond the self-bond
    unbond_tokens_new(
        &mut s,
        None,
        &validator.address,
        amount_del,
        current_epoch,
    )
    .unwrap();

    let val_stake_pre = read_validator_stake(
        &s,
        &params,
        &validator.address,
        current_epoch + params.pipeline_len - 1,
    )
    .unwrap();
    let val_stake_post = read_validator_stake(
        &s,
        &params,
        &validator.address,
        current_epoch + params.pipeline_len,
    )
    .unwrap();
    let val_delta = read_validator_delta_value(
        &s,
        &params,
        &validator.address,
        current_epoch + params.pipeline_len,
    )
    .unwrap();
    let unbond = unbond_handle(&validator.address, &validator.address);

    assert_eq!(val_delta, Some(-amount_del.change()));
    assert_eq!(
        unbond
            .at(&(unbond_epoch + params.pipeline_len + params.unbonding_len))
            .get(&s, &(self_bond_epoch + params.pipeline_len))
            .unwrap(),
        Some(amount)
    );
    assert_eq!(
        unbond
            .at(&(unbond_epoch + params.pipeline_len + params.unbonding_len))
            .get(&s, &Epoch::default())
            .unwrap(),
        Some(amount_del - amount)
    );
    assert_eq!(val_stake_pre, Some(validator.tokens + amount + amount_del));
    assert_eq!(val_stake_post, Some(validator.tokens + amount));

    // Unbond delegation
    unbond_tokens_new(
        &mut s,
        Some(&delegator),
        &validator.address,
        amount,
        current_epoch,
    )
    .unwrap();

    let val_stake_pre = read_validator_stake(
        &s,
        &params,
        &validator.address,
        current_epoch + params.pipeline_len - 1,
    )
    .unwrap();
    let val_stake_post = read_validator_stake(
        &s,
        &params,
        &validator.address,
        current_epoch + params.pipeline_len,
    )
    .unwrap();
    let val_delta = read_validator_delta_value(
        &s,
        &params,
        &validator.address,
        current_epoch + params.pipeline_len,
    )
    .unwrap();
    let unbond = unbond_handle(&delegator, &validator.address);

    assert_eq!(val_delta, Some(-(amount + amount_del).change()));
    assert_eq!(
        unbond
            .at(&(unbond_epoch + params.pipeline_len + params.unbonding_len))
            .get(&s, &(delegation_epoch + params.pipeline_len))
            .unwrap(),
        Some(amount)
    );
    assert_eq!(val_stake_pre, Some(validator.tokens + amount + amount_del));
    assert_eq!(val_stake_post, Some(validator.tokens));

    let withdrawable_offset = params.unbonding_len + params.pipeline_len;

    // Advance to withdrawable epoch
    for _ in 0..withdrawable_offset {
        current_epoch = advance_epoch(&mut s, &params);
    }
    dbg!(current_epoch);

    let pos_balance = s
        .read::<token::Amount>(&token::balance_key(
            &staking_token_address(),
            &super::ADDRESS,
        ))
        .unwrap();

    assert_eq!(Some(pos_balance_pre + amount + amount_del), pos_balance);

    // Withdraw the self-unbond
    withdraw_tokens_new(&mut s, None, &validator.address, current_epoch)
        .unwrap();
    let unbond = unbond_handle(&validator.address, &validator.address);
    let unbond_iter = unbond.iter(&s).unwrap().next();
    assert!(unbond_iter.is_none());

    let pos_balance = s
        .read::<token::Amount>(&token::balance_key(
            &staking_token_address(),
            &super::ADDRESS,
        ))
        .unwrap();
    assert_eq!(Some(pos_balance_pre + amount), pos_balance);

    // Withdraw the delegation unbond
    withdraw_tokens_new(
        &mut s,
        Some(&delegator),
        &validator.address,
        current_epoch,
    )
    .unwrap();
    let unbond = unbond_handle(&delegator, &validator.address);
    let unbond_iter = unbond.iter(&s).unwrap().next();
    assert!(unbond_iter.is_none());

    let pos_balance = s
        .read::<token::Amount>(&token::balance_key(
            &staking_token_address(),
            &super::ADDRESS,
        ))
        .unwrap();
    assert_eq!(Some(pos_balance_pre), pos_balance);
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

    let num_active_before = read_num_active_validators(&s).unwrap();
    assert_eq!(
        min(validators.len() as u64, params.max_validator_slots),
        num_active_before
    );

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

    let num_active_after = read_num_active_validators(&s).unwrap();
    assert_eq!(
        if validators.len() as u64 >= params.max_validator_slots {
            num_active_before
        } else {
            num_active_before + 1
        },
        num_active_after
    );

    // Advance to epoch 2
    current_epoch = advance_epoch(&mut s, &params);

    // Self-bond to the new validator
    let amount = token::Amount::from(100_500_000);
    credit_tokens(&mut s, &staking_token_address(), &new_validator, amount)
        .unwrap();
    bond_tokens_new(&mut s, None, &new_validator, amount, current_epoch)
        .unwrap();

    // Check the bond delta
    let bond_handle = bond_handle(&new_validator, &new_validator);
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let delta = bond_handle
        .get_delta_val(&s, pipeline_epoch, &params)
        .unwrap();
    assert_eq!(delta, Some(amount.change()));

    // Check the validator in the validator set -
    // If the active validator slots are full and all the genesis validators
    // have stake GTE the new validator's self-bond amount, the validator should
    // be added to the inactive set, or the active otherwise
    if params.max_validator_slots <= validators.len() as u64
        && validators
            .iter()
            .all(|validator| validator.tokens >= amount)
    {
        let set = read_inactive_validator_set_addresses_with_stake(
            &s,
            pipeline_epoch,
        )
        .unwrap();
        assert!(set.into_iter().any(
            |WeightedValidatorNew {
                 bonded_stake,
                 address,
             }| {
                address == new_validator && bonded_stake == amount
            }
        ));
    } else {
        let set =
            read_active_validator_set_addresses_with_stake(&s, pipeline_epoch)
                .unwrap();
        assert!(set.into_iter().any(
            |WeightedValidatorNew {
                 bonded_stake,
                 address,
             }| {
                address == new_validator && bonded_stake == amount
            }
        ));
    }

    // Advance to epoch 3
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

#[test]
fn test_validator_raw_hash() {
    let mut storage = TestWlStorage::default();
    let address = address::testing::established_address_1();
    let consensus_sk = key::testing::keypair_1();
    let consensus_pk = consensus_sk.to_public();
    let expected_raw_hash = key::tm_consensus_key_raw_hash(&consensus_pk);

    assert!(
        find_validator_by_raw_hash(&storage, &expected_raw_hash)
            .unwrap()
            .is_none()
    );
    write_validator_address_raw_hash(&mut storage, &address, &consensus_pk)
        .unwrap();
    let found =
        find_validator_by_raw_hash(&storage, &expected_raw_hash).unwrap();
    assert_eq!(found, Some(address));
}

#[test]
fn test_validator_sets() {
    let mut s = TestWlStorage::default();
    // Only 2 active validator slots
    let params = PosParams {
        max_validator_slots: 2,
        ..Default::default()
    };
    let seed = "seed";
    let mut address_gen = EstablishedAddressGen::new(seed);
    let mut gen_validator = || address_gen.generate_address(seed);

    // Start with one genesis validator
    let epoch = Epoch::default();
    let pipeline_epoch = epoch + params.pipeline_len;
    let pk1 = key::testing::keypair_1().to_public();
    let (val1, stake1) = (gen_validator(), token::Amount::whole(1));
    init_genesis_new(
        &mut s,
        &params,
        [GenesisValidator {
            address: val1.clone(),
            tokens: stake1,
            consensus_key: pk1,
            commission_rate: Decimal::new(1, 1),
            max_commission_rate_change: Decimal::new(1, 1),
        }]
        .into_iter(),
        epoch,
    );

    // Insert another validator with the same stake
    let (val2, stake2) = (gen_validator(), token::Amount::whole(1));
    insert_validator_into_validator_set(
        &mut s,
        &params,
        &val2,
        stake2,
        pipeline_epoch,
    )
    .unwrap();

    let active_vals: Vec<_> = active_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(matches!(
        &active_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        },
        address) if address == &val1 && stake == &stake1 && *position == Position::default()
    ));
    assert!(matches!(
        &active_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        },
        address) if address == &val2 && stake == &stake2 && *position == Position::ONE
    ));

    // Insert another validator with a greater stake, it should replace 2nd
    // active validator, which should become inactive
    let (val3, stake3) = (gen_validator(), token::Amount::whole(10));
    insert_validator_into_validator_set(
        &mut s,
        &params,
        &val3,
        stake3,
        pipeline_epoch,
    )
    .unwrap();

    let active_vals: Vec<_> = active_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(matches!(
        &active_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        },
        address) if address == &val1 && stake == &stake1 && *position == Position::default()
    ));
    assert!(matches!(
        &active_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        },
        address) if address == &val3 && stake == &stake3 && *position == Position::default()
    ));
    let inactive_vals: Vec<_> = inactive_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(matches!(
        &inactive_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        },
        address) if address == &val2 && stake == &stake2 && *position == Position::default()
    ));
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

                let commission_rate = Decimal::new(5, 2);
                let max_commission_rate_change = Decimal::new(1, 3);
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
