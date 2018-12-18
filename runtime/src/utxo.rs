use primitives::{Signature, H256};
use rstd::collections::btree_map::BTreeMap;
use runtime_io::ed25519_verify;
use runtime_primitives::traits::{BlakeTwo256, Hash};
use srml_support::{
	dispatch::{Result, Vec},
	StorageMap,
};
use system::ensure_inherent;

pub trait Trait: system::Trait {
	type Event: From<Event> + Into<<Self as system::Trait>::Event>;
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash)]
pub struct Transaction {
	pub inputs: Vec<TransactionInput>,
	pub outputs: Vec<TransactionOutput>,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash)]
pub struct TransactionInput {
	pub parent_output: H256,
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
			Self::update_storage(&transaction);

			Self::deposit_event(Event::TransactionExecuted(transaction));

			Ok(())
		}
	}
}

decl_storage! {
	trait Store for Module<T: Trait> as Utxo {
		UnspentOutputs get(utxo): map H256 => Option<TransactionOutput>;
	}
}

decl_event!(
	pub enum Event {
		TransactionExecuted(Transaction),
	}
);

impl<T: Trait> Module<T> {
	/// Check transaction for validity.
	///
	/// Ensures that:
	/// - all inputs match to existing and unspent outputs
	/// - each unspent output is used exactly once
	/// - each output is defined exactly once
	/// - total output value must not exceed total input value
	/// - new outputs do not collide with existing ones
	/// - provided signatures are valid
	fn check_transaction(transaction: &Transaction) -> Result {
		{
			let input_set: BTreeMap<_, ()> = transaction
				.inputs
				.iter()
				.map(|input| (input, ()))
				.collect();

			ensure!(
				input_set.len() == transaction.inputs.len(),
				"each input must be used only once"
			);
		}

		{
			let output_set: BTreeMap<_, ()> = transaction
				.outputs
				.iter()
				.map(|output| (output, ()))
				.collect();

			ensure!(
				output_set.len() == transaction.outputs.len(),
				"each output must be defined only once"
			);
		}

		let total_input = transaction.inputs.iter().fold(Ok(0u128), |sum, input| {
			sum.and_then(|sum| {
				// Fetch UTXO from the storage
				let output = match Self::utxo(&input.parent_output) {
					Some(output) => output,
					None => return Err("all linked outputs must exist and be unspent"),
				};

				// Check that we're authorized to use it
				ensure!(
					ed25519_verify(
						input.signature.as_fixed_bytes(),
						input.parent_output.as_fixed_bytes(),
						&output.pubkey
					),
					"signature must be valid"
				);

				// Add the value to the input total
				match sum.checked_add(output.value) {
					Some(sum) => Ok(sum),
					None => Err("input value overflow"),
				}
			})
		})?;

		let total_output = transaction.outputs.iter().fold(Ok(0u128), |sum, output| {
			sum.and_then(|sum| {
				let hash = BlakeTwo256::hash_of(output);
				ensure!(!<UnspentOutputs<T>>::exists(hash), "UTXO already exists");

				match sum.checked_add(output.value) {
					Some(sum) => Ok(sum),
					None => Err("output value overflow"),
				}
			})
		})?;

		ensure!(
			total_input >= total_output,
			"output value must not exceed input value"
		);

		Ok(())
	}

	/// Update storage to reflect changes made by transaction
	fn update_storage(transaction: &Transaction) {
		// Remove all used UTXO to mark them as spent
		for input in &transaction.inputs {
			<UnspentOutputs<T>>::remove(input.parent_output);
		}

		// Add new UTXO to be used by future transactions
		for output in &transaction.outputs {
			let hash = BlakeTwo256::hash_of(output);
			<UnspentOutputs<T>>::insert(hash, output);
		}
	}

	fn deposit_event(event: Event) {
		let event = <T as Trait>::Event::from(event).into();
		<system::Module<T>>::deposit_event(event);
	}
}
