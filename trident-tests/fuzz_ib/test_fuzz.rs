use trident_fuzz::fuzzing::*;

#[derive(Default)]
struct AccountAddresses {}

#[derive(FuzzTestMethods)]
struct IbFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl IbFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        // TODO: initialize two vault accounts with edge-case amounts.
    }

    #[flow]
    fn integer_bug_flow(&mut self) {
        // TODO: fuzz transfer amount for ib_transfer.
        // The expected finding is wrapping underflow/overflow behavior.
    }
}

fn main() {
    IbFuzz::fuzz(400, 50);
}
