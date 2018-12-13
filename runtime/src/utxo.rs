use primitives::H256;
use srml_support::{StorageValue, dispatch::{Vec, Result}};

pub trait Trait: system::Trait {}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn spend(transaction: Transaction) -> Result {
			unimplemented!()
		}
	}
}

decl_storage! {
	trait Store for Module<T: Trait> as Demo {
		UnspentOutputs: map H256 => TransactionOutput;
	}
}

#[derive(Debug, PartialEq, Default, Clone, Encode, Decode)]
pub struct Transaction {
	pub inputs: Vec<TransactionInput>,
	pub outputs: Vec<TransactionOutput>,
	pub lock_time: u32,
}

#[derive(Debug, PartialEq, Default, Clone, Encode, Decode)]
pub struct TransactionInput {
	pub previous_output: OutPoint,
	pub signature: Bytes,
}

#[derive(Debug, Default, PartialEq, Clone, Encode, Decode)]
pub struct TransactionOutput {
	pub value: u64,
	pub pubkey: Bytes,
}

#[derive(Debug, PartialEq, Eq, Clone, Default, Encode, Decode)]
pub struct OutPoint {
	pub hash: H256,
	pub index: u32,
}

#[derive(Default, Debug, PartialEq, Clone, Eq, Hash, Encode, Decode)]
pub struct Bytes(Vec<u8>);
