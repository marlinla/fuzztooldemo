use trident_fuzz::fuzzing::*;

#[derive(Default)]
struct AccountAddresses {}

#[derive(FuzzTestMethods)]
struct AcpiFuzz {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl AcpiFuzz {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        // TODO: initialize DemoState with a trusted CPI program id.
    }

    #[flow]
    fn arbitrary_cpi_flow(&mut self) {
        // TODO: mutate callee_program so it differs from trusted_cpi_program.
        // The expected finding is CPI execution toward attacker-selected program id.
    }
}

fn main() {
    AcpiFuzz::fuzz(400, 50);
}
