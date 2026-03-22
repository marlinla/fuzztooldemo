use trident_fuzz::fuzzing::*;

#[derive(Default)]
struct AccountAddresses {}

#[derive(FuzzTestMethods)]
struct MscFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl MscFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        // TODO: initialize DemoState and accounts used by msc_set_secret.
    }

    #[flow]
    fn missing_signer_check_flow(&mut self) {
        // TODO: call msc_set_secret while mutating authority account metadata.
        // The expected finding is unauthorized state mutation without signer.
    }
}

fn main() {
    MscFuzz::fuzz(400, 50);
}
