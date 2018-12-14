use primitives::H256;
use rstd::collections::btree_map::BTreeMap;
use runtime_io::ed25519_verify;
use runtime_primitives::traits::{BlakeTwo256, Hash};
use srml_support::{
	dispatch::{Result, Vec},
	StorageMap,
};
use system::ensure_inherent;

pub trait Trait: system::Trait {}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		pub fn execute(origin, transaction: Transaction) -> Result {
			ensure_inherent(origin)?;

			// In order to execute the transaction we need to ensure that:
			// - all inputs match to unspent outputs
			// - each unspent output is used exactly once
			// - each output is defined exactly once
			// - sum of output value is less than sum of input value
			// - provided signatures must be valid

			let inputs_valid = transaction.inputs
				.iter()
				.map(|input| BlakeTwo256::hash_of(input))
				.all(|hash| <UnspentOutputs<T>>::exists(&hash));
			ensure!(inputs_valid, "all inputs must exist and be unspent");

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

			let input_value: u128 = transaction.inputs
				.iter()
				.map(|input| <UnspentOutputs<T>>::get(&input.linked_output).value)
				.fold(Ok(0u128), |sum, value| {
					sum.and_then(|s|
						match s.checked_add(value) {
							Some(sum) => Ok(sum),
							None => Err("input value overflow"),
						}
					)
				})?;

			let output_value: u128 = transaction.outputs
				.iter()
				.map(|output| output.value)
				.fold(Ok(0u128), |sum, value| {
					sum.and_then(|s|
						match s.checked_add(value) {
							Some(sum) => Ok(sum),
							None => Err("output value overflow"),
						}
					)
				})?;

			ensure!(input_value >= output_value, "output value must not exceed input value");

			unimplemented!()
		}
	}
}

decl_storage! {
	trait Store for Module<T: Trait> as Demo {
		UnspentOutputs: map H256 => TransactionOutput;
	}
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
	pub linked_output: H256,
	pub signature: Bytes,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct TransactionOutput {
	pub value: u128,
	pub pubkey: Bytes,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct Bytes(Vec<u8>);
