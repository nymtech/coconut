use crate::{Base58, BlindSignRequest, BlindedSignature, Theta};

macro_rules! impl_clone {
    ($struct:ident) => {
        impl Clone for $struct {
            fn clone(&self) -> Self {
                Self::try_from_bs58(self.to_bs58()).unwrap()
            }
        }
    };
}

impl_clone!(BlindSignRequest);
impl_clone!(BlindedSignature);
impl_clone!(Theta);
