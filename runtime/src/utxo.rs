use primitives::{Signature, H256};
use rstd::collections::btree_map::BTreeMap;
use runtime_io::ed25519_verify;
use runtime_primitives::traits::{BlakeTwo256, Hash};
use srml_support::{
	dispatch::{Result, Vec},
	StorageMap,
};
use system::ensure_inherent;

pub trait Trait: system::Trait {}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash)]
pub struct Transaction {
	pub inputs: Vec<TransactionInput>,
	pub outputs: Vec<TransactionOutput>,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash)]
pub struct TransactionInput {
	pub linked_output: H256,
	pub signature: Signature,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct TransactionOutput {
	pub value: u128,
	pub pubkey: H256,
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		pub fn execute(origin, transaction: Transaction) -> Result {
			ensure_inherent(origin)?;

			Self::check_transaction(&transaction)?;
			Self::spend_transaction(transaction)?;

			Ok(())
		}
	}
}

decl_storage! {
	trait Store for Module<T: Trait> as Demo {
		UnspentOutputs get(utxo): map H256 => Option<TransactionOutput>;
	}
}

impl<T: Trait> Module<T> {
	fn check_transaction(transaction: &Transaction) -> Result {
		// We need to ensure that:
		// - all inputs match to existing and unspent outputs
		// - each unspent output is used exactly once
		// - each output is defined exactly once
		// - sum of output value is less than sum of input value
		// - provided signatures are valid

		{
			let input_set: BTreeMap<_, ()> = transaction.inputs
				.iter()
				.map(|input| (input, ()))
				.collect();

			ensure!(input_set.len() == transaction.inputs.len(), "each input must be used only once");
		}

		{
			let output_set: BTreeMap<_, ()> = transaction.outputs
				.iter()
				.map(|output| (output, ()))
				.collect();

			ensure!(output_set.len() == transaction.outputs.len(), "each output must be defined only once");
		}

		let total_input: u128 = transaction.inputs.iter().fold(Ok(0u128), |sum, input| {
			sum.and_then(|sum| {
				// Fetch UTXO from the storage
				let output = match Self::utxo(&input.linked_output) {
					Some(output) => output,
					None => return Err("all linked outputs must exist and be unspent"),
				};

				// Check that we're authorized to use it
				ensure!(
					ed25519_verify(
						input.signature.as_fixed_bytes(),
						input.linked_output.as_fixed_bytes(),
						&output.pubkey
					),
					"signature must be valid"
				);

				// Add the value to the incoming sum
				match sum.checked_add(output.value) {
					Some(sum) => Ok(sum),
					None => Err("input value overflow"),
				}
			})
		})?;

		let total_output: u128 = transaction.outputs.iter().map(|output| output.value).fold(
			Ok(0u128),
			|sum, value| {
				sum.and_then(|s| match s.checked_add(value) {
					Some(sum) => Ok(sum),
					None => Err("output value overflow"),
				})
			},
		)?;

		ensure!(total_input >= total_output, "output value must not exceed input value");

		Ok(())
	}

	fn spend_transaction(transaction: Transaction) -> Result {
		// In order to spend transaction we need to:
		// - remove used UTXO's
		// - add new UTXO's created by this transaction

		for input in transaction.inputs {
			<UnspentOutputs<T>>::remove(input.linked_output);
		}

		for output in transaction.outputs {
			let hash = BlakeTwo256::hash_of(&output);
			ensure!(!<UnspentOutputs<T>>::exists(hash), "UTXO already exists"); // FIXME
			<UnspentOutputs<T>>::insert(hash, output);
		}

		Ok(())
	}
}
