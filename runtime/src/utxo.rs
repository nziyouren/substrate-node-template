use parity_codec::Encode;
use primitives::{Signature, H256};
use rstd::collections::btree_map::BTreeMap;
use runtime_io::ed25519_verify;
use srml_support::dispatch::{Result, Vec};
use system::ensure_inherent;

pub trait Trait: system::Trait {}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		pub fn execute(origin, transaction: Transaction) -> Result {
			ensure_inherent(origin)?;

			// In order to execute the transaction we need to ensure that:
			// - all inputs match to existing and unspent outputs
			// - each unspent output is used exactly once
			// - each output is defined exactly once
			// - sum of output value is less than sum of input value
			// - provided signatures must be valid

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
				.map(|input| (input.signature, Self::utxo(&input.linked_output)))
				.fold(Ok(0u128), |sum, (signature, output)| {
					ensure!(output.is_some(), "all linked outputs must exist and be unspent");
					let output = output.unwrap();

					let digest = output.encode();
					ensure!(ed25519_verify(signature.as_fixed_bytes(), &digest, &output.pubkey), "signature must be valid");

					sum.and_then(|s|
						match s.checked_add(output.value) {
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
		UnspentOutputs get(utxo): map H256 => Option<TransactionOutput>;
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
	pub signature: Signature,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct TransactionOutput {
	pub value: u128,
	pub pubkey: H256,
}
