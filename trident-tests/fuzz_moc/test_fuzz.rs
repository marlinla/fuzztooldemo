use trident_fuzz::fuzzing::*;

#[derive(Default)]
struct AccountAddresses {}

#[derive(FuzzTestMethods)]
struct MocFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl MocFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        // TODO: initialize DemoState and attacker-controlled policy_account.
    }

    #[flow]
    fn missing_owner_check_flow(&mut self) {
        // TODO: fuzz policy_account data to bypass trust checks in moc_set_secret.
        // The expected finding is untrusted account data controlling state updates.
    }
}

fn main() {
    MocFuzz::fuzz(400, 50);
}
