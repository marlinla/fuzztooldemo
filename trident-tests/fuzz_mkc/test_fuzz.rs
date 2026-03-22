use trident_fuzz::fuzzing::*;

#[derive(Default)]
struct AccountAddresses {}

#[derive(FuzzTestMethods)]
struct MkcFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl MkcFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        // TODO: initialize DemoState with a trusted clock sysvar key.
    }

    #[flow]
    fn missing_key_check_flow(&mut self) {
        // TODO: pass spoofed clock_like account to mkc_gate.
        // The expected finding is acceptance of non-sysvar account data.
    }
}

fn main() {
    MkcFuzz::fuzz(400, 50);
}
