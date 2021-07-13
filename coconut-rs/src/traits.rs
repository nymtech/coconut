pub trait Bytable {
    fn to_byte_vec(&self) -> Vec<u8>;

    fn from_byte_slice(slice: &[u8]) -> Self;
}

pub trait Base58
where
    Self: Bytable + Sized,
{
    fn from_bs58(x: &str) -> Self {
        Self::from_byte_slice(&bs58::decode(x).into_vec().unwrap())
    }
    fn to_bs58(&self) -> String {
        bs58::encode(self.to_byte_vec()).into_string()
    }
}
