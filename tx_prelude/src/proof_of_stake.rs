//! Proof of Stake system integration with functions for transactions

use namada_core::types::key::common;
use namada_core::types::transaction::InitValidator;
use namada_core::types::{key, token};
pub use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::storage::{
    bond_key, params_key, total_deltas_key, unbond_key,
    validator_address_raw_hash_key, validator_commission_rate_key,
    validator_consensus_key_key, validator_deltas_key,
    validator_max_commission_rate_change_key, validator_set_key,
    validator_slashes_key, validator_state_key, BondId, Bonds, TotalDeltas,
    Unbonds, ValidatorConsensusKeys, ValidatorDeltas, ValidatorSets,
};
use namada_proof_of_stake::types::{CommissionRates, ValidatorStates};
pub use namada_proof_of_stake::{
    epoched, parameters, types, PosActions as PosWrite, PosReadOnly as PosRead,
};
use rust_decimal::Decimal;

use super::*;

impl Ctx {
    /// Self-bond tokens to a validator when `source` is `None` or equal to
    /// the `validator` address, or delegate tokens from the `source` to the
    /// `validator`.
    pub fn bond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
    ) -> TxResult {
        let current_epoch = self.get_block_epoch()?;
        namada_proof_of_stake::PosActions::bond_tokens(
            self,
            source,
            validator,
            amount,
            current_epoch,
        )
    }

    /// Unbond self-bonded tokens from a validator when `source` is `None` or
    /// equal to the `validator` address, or unbond delegated tokens from
    /// the `source` to the `validator`.
    pub fn unbond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
    ) -> TxResult {
        let current_epoch = self.get_block_epoch()?;
        namada_proof_of_stake::PosActions::unbond_tokens(
            self,
            source,
            validator,
            amount,
            current_epoch,
        )
    }

    /// Withdraw unbonded tokens from a self-bond to a validator when `source`
    /// is `None` or equal to the `validator` address, or withdraw unbonded
    /// tokens delegated to the `validator` to the `source`.
    pub fn withdraw_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
    ) -> EnvResult<token::Amount> {
        let current_epoch = self.get_block_epoch()?;
        namada_proof_of_stake::PosActions::withdraw_tokens(
            self,
            source,
            validator,
            current_epoch,
        )
    }

    /// Change validator commission rate.
    pub fn change_validator_commission_rate(
        &mut self,
        validator: &Address,
        rate: &Decimal,
    ) -> TxResult {
        let current_epoch = self.get_block_epoch()?;
        namada_proof_of_stake::PosActions::change_validator_commission_rate(
            self,
            validator,
            *rate,
            current_epoch,
        )
    }

    /// Attempt to initialize a validator account. On success, returns the
    /// initialized validator account's address.
    pub fn init_validator(
        &mut self,
        InitValidator {
            account_key,
            consensus_key,
            protocol_key,
            dkg_key,
            commission_rate,
            max_commission_rate_change,
            validator_vp_code,
        }: InitValidator,
    ) -> EnvResult<Address> {
        let current_epoch = self.get_block_epoch()?;
        // Init validator account
        let validator_address = self.init_account(&validator_vp_code)?;
        let pk_key = key::pk_key(&validator_address, 0);
        self.write(&pk_key, &account_key)?;
        let protocol_pk_key = key::protocol_pk_key(&validator_address);
        self.write(&protocol_pk_key, &protocol_key)?;
        let dkg_pk_key = key::dkg_session_keys::dkg_pk_key(&validator_address);
        self.write(&dkg_pk_key, &dkg_key)?;

        self.become_validator(
            &validator_address,
            &consensus_key,
            current_epoch,
            commission_rate,
            max_commission_rate_change,
        )?;

        Ok(validator_address)
    }
}

namada_proof_of_stake::impl_pos_read_only! {
    impl namada_proof_of_stake::PosReadOnly for Ctx
}

impl namada_proof_of_stake::PosActions for Ctx {
    fn write_pos_params(
        &mut self,
        params: &PosParams,
    ) -> storage_api::Result<()> {
        self.write(&params_key(), params)
    }

    fn write_validator_address_raw_hash(
        &mut self,
        address: &Address,
        consensus_key: &common::PublicKey,
    ) -> storage_api::Result<()> {
        let raw_hash = key::tm_consensus_key_raw_hash(consensus_key);
        self.write(&validator_address_raw_hash_key(raw_hash), address)
    }

    fn write_validator_consensus_key(
        &mut self,
        key: &Address,
        value: ValidatorConsensusKeys,
    ) -> storage_api::Result<()> {
        self.write(&validator_consensus_key_key(key), &value)
    }

    fn write_validator_state(
        &mut self,
        key: &Address,
        value: ValidatorStates,
    ) -> storage_api::Result<()> {
        self.write(&validator_state_key(key), &value)
    }

    fn write_validator_commission_rate(
        &mut self,
        key: &Address,
        value: CommissionRates,
    ) -> storage_api::Result<()> {
        self.write(&validator_commission_rate_key(key), &value)
    }

    fn write_validator_max_commission_rate_change(
        &mut self,
        key: &Address,
        value: Decimal,
    ) -> storage_api::Result<()> {
        self.write(&validator_max_commission_rate_change_key(key), value)
    }

    fn write_validator_deltas(
        &mut self,
        key: &Address,
        value: ValidatorDeltas,
    ) -> storage_api::Result<()> {
        self.write(&validator_deltas_key(key), &value)
    }

    fn write_bond(
        &mut self,
        key: &BondId,
        value: Bonds,
    ) -> storage_api::Result<()> {
        self.write(&bond_key(key), &value)
    }

    fn write_unbond(
        &mut self,
        key: &BondId,
        value: Unbonds,
    ) -> storage_api::Result<()> {
        self.write(&unbond_key(key), &value)
    }

    fn write_validator_set(
        &mut self,
        value: ValidatorSets,
    ) -> storage_api::Result<()> {
        self.write(&validator_set_key(), &value)
    }

    fn write_total_deltas(
        &mut self,
        value: TotalDeltas,
    ) -> storage_api::Result<()> {
        self.write(&total_deltas_key(), &value)
    }

    fn delete_bond(&mut self, key: &BondId) -> storage_api::Result<()> {
        self.delete(&bond_key(key))
    }

    fn delete_unbond(&mut self, key: &BondId) -> storage_api::Result<()> {
        self.delete(&unbond_key(key))
    }

    fn transfer(
        &mut self,
        token: &Address,
        amount: token::Amount,
        src: &Address,
        dest: &Address,
    ) -> storage_api::Result<()> {
        crate::token::transfer(
            self, src, dest, token, None, amount, &None, &None,
        )
    }
}
