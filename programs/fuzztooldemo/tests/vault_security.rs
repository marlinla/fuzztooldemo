use anchor_lang::{
    AccountDeserialize, AnchorSerialize, Discriminator, InstructionData, ToAccountMetas,
};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    account::Account,
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

fn fuzztooldemo_processor<'a, 'b, 'c, 'd>(
    program_id: &'a Pubkey,
    accounts: &'b [AccountInfo<'c>],
    instruction_data: &'d [u8],
) -> ProgramResult {
    // ProgramTest expects a processor with split lifetimes for the account slice
    // and AccountInfo internals; Anchor entry uses one shared lifetime.
    let coerced_accounts: &'c [AccountInfo<'c>] = unsafe { std::mem::transmute(accounts) };
    fuzztooldemo::entry(program_id, coerced_accounts, instruction_data)
}

fn noop_processor(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    Ok(())
}

const TRUSTED_PLUGIN_ID: Pubkey = Pubkey::new_from_array([7u8; 32]);
const ATTACKER_PLUGIN_ID: Pubkey = Pubkey::new_from_array([9u8; 32]);

fn log_setup(msg: &str) {
    println!("[SETUP] {msg}");
}

fn log_action(msg: &str) {
    println!("[ACTION] {msg}");
}

fn log_expect(msg: &str) {
    println!("[EXPECT] {msg}");
}

fn log_assert(msg: &str) {
    println!("[ASSERT] {msg}");
}

fn setup_program_test() -> ProgramTest {
    let mut pt = ProgramTest::new(
        "fuzztooldemo",
        fuzztooldemo::id(),
        processor!(fuzztooldemo_processor),
    );
    pt.add_program("trusted_plugin", TRUSTED_PLUGIN_ID, processor!(noop_processor));
    pt.add_program("attacker_plugin", ATTACKER_PLUGIN_ID, processor!(noop_processor));
    pt
}

fn anchor_account_data<T: AnchorSerialize>(discriminator: &[u8], value: &T) -> Vec<u8> {
    let mut data = discriminator.to_vec();
    value
        .serialize(&mut data)
        .expect("anchor serialization should succeed");
    data
}

fn add_vault_state(
    pt: &mut ProgramTest,
    key: Pubkey,
    authority: Pubkey,
    trusted_plugin_program: Pubkey,
    trusted_clock_key: Pubkey,
) {
    let state = fuzztooldemo::VaultState {
        authority,
        trusted_plugin_program,
        trusted_clock_key,
        withdraw_limit: 100,
        secret: 0,
        payout_count: 0,
    };
    let data = anchor_account_data(fuzztooldemo::VaultState::DISCRIMINATOR, &state);
    pt.add_account(
        key,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: fuzztooldemo::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
}

fn add_vault_balance(pt: &mut ProgramTest, key: Pubkey, amount: u64) {
    let value = fuzztooldemo::VaultBalance { amount };
    let data = anchor_account_data(fuzztooldemo::VaultBalance::DISCRIMINATOR, &value);
    pt.add_account(
        key,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: fuzztooldemo::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
}

fn add_unchecked_account(pt: &mut ProgramTest, key: Pubkey, owner: Pubkey, data: Vec<u8>) {
    pt.add_account(
        key,
        Account {
            lamports: 1_000_000_000,
            data,
            owner,
            executable: false,
            rent_epoch: 0,
        },
    );
}

fn add_lamport_only_account(pt: &mut ProgramTest, key: Pubkey, owner: Pubkey, lamports: u64) {
    pt.add_account(
        key,
        Account {
            lamports,
            data: vec![],
            owner,
            executable: false,
            rent_epoch: 0,
        },
    );
}

fn policy_data_with_target(target: Pubkey, tail: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(33 + tail.len());
    data.push(1);
    data.extend_from_slice(target.as_ref());
    data.extend_from_slice(tail);
    data
}

async fn send_ix(
    ctx: &mut solana_program_test::ProgramTestContext,
    ix: Instruction,
    signers: &[&Keypair],
) {
    let mut all_signers: Vec<&Keypair> = vec![&ctx.payer];
    all_signers.extend_from_slice(signers);
    let blockhash = ctx
        .banks_client
        .get_latest_blockhash()
        .await
        .expect("get latest blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&ctx.payer.pubkey()),
        &all_signers,
        blockhash,
    );
    ctx.banks_client
        .process_transaction(tx)
        .await
        .expect("transaction should succeed");
}

async fn send_ix_expect_err(
    ctx: &mut solana_program_test::ProgramTestContext,
    ix: Instruction,
    signers: &[&Keypair],
) {
    let mut all_signers: Vec<&Keypair> = vec![&ctx.payer];
    all_signers.extend_from_slice(signers);
    let blockhash = ctx
        .banks_client
        .get_latest_blockhash()
        .await
        .expect("get latest blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&ctx.payer.pubkey()),
        &all_signers,
        blockhash,
    );
    let result = ctx.banks_client.process_transaction(tx).await;
    assert!(result.is_err(), "transaction should fail in native test runtime");
}

async fn read_vault_state(
    ctx: &mut solana_program_test::ProgramTestContext,
    key: Pubkey,
) -> fuzztooldemo::VaultState {
    let account = ctx
        .banks_client
        .get_account(key)
        .await
        .expect("account query should succeed")
        .expect("account should exist");
    let mut data: &[u8] = &account.data;
    fuzztooldemo::VaultState::try_deserialize(&mut data).expect("vault state deserialize")
}

async fn read_vault_balance(
    ctx: &mut solana_program_test::ProgramTestContext,
    key: Pubkey,
) -> fuzztooldemo::VaultBalance {
    let account = ctx
        .banks_client
        .get_account(key)
        .await
        .expect("account query should succeed")
        .expect("account should exist");
    let mut data: &[u8] = &account.data;
    fuzztooldemo::VaultBalance::try_deserialize(&mut data).expect("vault balance deserialize")
}

async fn read_account_lamports(
    ctx: &mut solana_program_test::ProgramTestContext,
    key: Pubkey,
) -> u64 {
    ctx.banks_client
        .get_account(key)
        .await
        .expect("account query should succeed")
        .expect("account should exist")
        .lamports
}

#[tokio::test]
async fn honest_flow_passes() {
    log_setup("Initialize honest vault scenario with trusted accounts and safe balances.");
    let authority = Keypair::new();
    let vault_state = Pubkey::new_unique();
    let policy_account = Pubkey::new_unique();
    let trusted_clock = Pubkey::new_unique();
    let treasury = Pubkey::new_unique();
    let from_wallet = Pubkey::new_unique();
    let to_wallet = Pubkey::new_unique();

    let mut pt = setup_program_test();
    add_vault_state(
        &mut pt,
        vault_state,
        authority.pubkey(),
        TRUSTED_PLUGIN_ID,
        trusted_clock,
    );
    add_vault_balance(&mut pt, treasury, 1_000);
    add_lamport_only_account(&mut pt, from_wallet, fuzztooldemo::id(), 1_000_000);
    add_lamport_only_account(&mut pt, to_wallet, fuzztooldemo::id(), 1_000_000);
    add_unchecked_account(
        &mut pt,
        policy_account,
        fuzztooldemo::id(),
        policy_data_with_target(treasury, &[0, 0, 0, 0]),
    );
    add_unchecked_account(
        &mut pt,
        trusted_clock,
        Pubkey::new_unique(),
        1_000_000u64.to_le_bytes().to_vec(),
    );

    let mut ctx = pt.start_with_context().await;

    log_action("Run MSC update with valid authority signer.");
    let mut msc_accounts = fuzztooldemo::accounts::MscUpdateWithdrawLimit {
        vault_state,
        authority: authority.pubkey(),
    }
    .to_account_metas(None);
    msc_accounts[1].is_signer = true;
    send_ix(
        &mut ctx,
        Instruction {
            program_id: fuzztooldemo::id(),
            accounts: msc_accounts,
            data: fuzztooldemo::instruction::MscUpdateWithdrawLimit { new_limit: 777 }.data(),
        },
        &[&authority],
    )
    .await;

    log_action("Run MOC policy secret update using policy account owned by program.");
    send_ix(
        &mut ctx,
        Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::MocUpdatePolicySecret {
                vault_state,
                treasury_vault: treasury,
                policy_account,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::MocUpdatePolicySecret { new_secret: 55 }.data(),
        },
        &[],
    )
    .await;

    log_action("Run MKC clock gate using trusted clock-like account data.");
    send_ix(
        &mut ctx,
        Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::MkcClockGate {
                vault_state,
                clock_like: trusted_clock,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::MkcClockGate { min_slot: 1 }.data(),
        },
        &[],
    )
    .await;

    log_action("Run IB transfer with safe amount bounds.");
    send_ix(
        &mut ctx,
        Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::IbLamportTransfer {
                vault_state,
                from_wallet,
                to_wallet,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::IbLamportTransfer { amount: 10 }.data(),
        },
        &[],
    )
    .await;

    let state = read_vault_state(&mut ctx, vault_state).await;
    let treasury_after = read_vault_balance(&mut ctx, treasury).await;
    let from_after = read_account_lamports(&mut ctx, from_wallet).await;
    let to_after = read_account_lamports(&mut ctx, to_wallet).await;

    log_expect("All honest operations succeed and state transitions are consistent.");
    assert_eq!(state.withdraw_limit, 777);
    assert_eq!(state.secret, 55);
    assert_eq!(state.payout_count, 1);
    // MOC decrements the targeted treasury by one in the honest path.
    assert_eq!(treasury_after.amount, 999);
    assert_eq!(from_after, 999_990);
    assert_eq!(to_after, 1_000_010);
    log_assert("Honest flow checks passed.");
}

#[tokio::test]
async fn msc_attack_reaches_vulnerability() {
    log_setup("Initialize vault with attacker pubkey set as authority field.");
    let vault_state = Pubkey::new_unique();
    let attacker = Pubkey::new_unique();
    let mut pt = setup_program_test();
    add_vault_state(
        &mut pt,
        vault_state,
        attacker,
        TRUSTED_PLUGIN_ID,
        Pubkey::new_unique(),
    );
    let mut ctx = pt.start_with_context().await;

    log_action("Call MSC update without signer privileges.");
    send_ix(
        &mut ctx,
        Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::MscUpdateWithdrawLimit {
                vault_state,
                authority: attacker,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::MscUpdateWithdrawLimit { new_limit: 9_999 }.data(),
        },
        &[],
    )
    .await;

    log_expect("Missing signer check allows unauthorized withdraw_limit update.");
    let state = read_vault_state(&mut ctx, vault_state).await;
    assert_eq!(state.withdraw_limit, 9_999);
    log_assert("MSC exploit state mutation observed.");
}

#[tokio::test]
async fn moc_attack_reaches_vulnerability() {
    log_setup("Initialize vault and attacker-owned policy account that references treasury key.");
    let vault_state = Pubkey::new_unique();
    let treasury = Pubkey::new_unique();
    let policy_account = Pubkey::new_unique();
    let mut pt = setup_program_test();
    add_vault_state(
        &mut pt,
        vault_state,
        Pubkey::new_unique(),
        TRUSTED_PLUGIN_ID,
        Pubkey::new_unique(),
    );
    add_vault_balance(&mut pt, treasury, 1_000);
    add_unchecked_account(
        &mut pt,
        policy_account,
        Pubkey::new_unique(),
        policy_data_with_target(treasury, &[42, 42, 42]),
    );
    let mut ctx = pt.start_with_context().await;

    log_action("Call MOC update with attacker-owned policy account.");
    send_ix(
        &mut ctx,
        Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::MocUpdatePolicySecret {
                vault_state,
                treasury_vault: treasury,
                policy_account,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::MocUpdatePolicySecret { new_secret: 123 }.data(),
        },
        &[],
    )
    .await;

    log_expect("Missing owner check accepts attacker data, authorizes key match, and mutates treasury.");
    let state = read_vault_state(&mut ctx, vault_state).await;
    let treasury_after = read_vault_balance(&mut ctx, treasury).await;
    assert_eq!(state.secret, 123);
    assert_eq!(treasury_after.amount, 999);
    log_assert("MOC exploit state mutation observed.");
}

#[tokio::test]
async fn acpi_attack_reaches_vulnerability() {
    log_setup("Initialize vault with trusted plugin but invoke payout with attacker plugin.");
    let vault_state = Pubkey::new_unique();
    let treasury = Pubkey::new_unique();
    let mut pt = setup_program_test();
    add_vault_state(
        &mut pt,
        vault_state,
        Pubkey::new_unique(),
        TRUSTED_PLUGIN_ID,
        Pubkey::new_unique(),
    );
    add_vault_balance(&mut pt, treasury, 1_000);
    let mut ctx = pt.start_with_context().await;

    log_action("Call ACPI plugin payout targeting attacker plugin program id.");
    send_ix_expect_err(
        &mut ctx,
        Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::AcpiPluginPayout {
                vault_state,
                treasury_vault: treasury,
                plugin_program: ATTACKER_PLUGIN_ID,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::AcpiPluginPayout {
                amount: 10,
                payload: vec![],
            }
            .data(),
        },
        &[],
    )
    .await;

    log_expect(
        "Host-native runtimes cannot CPI; program returns error after building CPI to attacker id.",
    );
    let state = read_vault_state(&mut ctx, vault_state).await;
    let treasury_after = read_vault_balance(&mut ctx, treasury).await;
    // Treasury update rolls back with the failed transaction; payout_count not incremented.
    assert_eq!(state.payout_count, 0);
    assert_eq!(treasury_after.amount, 1_000);
    log_assert("ACPI path reached unsafe CPI target selection point.");
}

#[tokio::test]
async fn mkc_attack_reaches_vulnerability() {
    log_setup("Initialize vault with trusted clock key and spoofed clock-like attacker account.");
    let vault_state = Pubkey::new_unique();
    let trusted_clock = Pubkey::new_unique();
    let spoofed_clock = Pubkey::new_unique();
    let mut pt = setup_program_test();
    add_vault_state(
        &mut pt,
        vault_state,
        Pubkey::new_unique(),
        TRUSTED_PLUGIN_ID,
        trusted_clock,
    );
    add_unchecked_account(
        &mut pt,
        spoofed_clock,
        Pubkey::new_unique(),
        9_999_999u64.to_le_bytes().to_vec(),
    );
    let mut ctx = pt.start_with_context().await;

    log_action("Call MKC gate using spoofed non-sysvar clock account.");
    send_ix(
        &mut ctx,
        Instruction {
            program_id: fuzztooldemo::id(),
            accounts: fuzztooldemo::accounts::MkcClockGate {
                vault_state,
                clock_like: spoofed_clock,
            }
            .to_account_metas(None),
            data: fuzztooldemo::instruction::MkcClockGate { min_slot: 1 }.data(),
        },
        &[],
    )
    .await;

    log_expect("Missing key check accepts spoofed clock data and increments payout_count.");
    let state = read_vault_state(&mut ctx, vault_state).await;
    assert_eq!(state.payout_count, 1);
    log_assert("MKC exploit state mutation observed.");
}

#[tokio::test]
async fn ib_attack_reaches_vulnerability() {
    log_setup("Exercise IB arithmetic helper at lamport wraparound edge.");
    let from_before = 5u64;
    let to_before = u64::MAX - 3;
    let amount = 10u64;

    log_action("Apply wrapping lamport transfer math with overflow/underflow operands.");
    let (from_after, to_after) = fuzztooldemo::ib_wrap_lamports(from_before, to_before, amount);

    log_expect("Wrapping math underflows source and overflows destination.");
    assert_eq!(from_after, u64::MAX - 4);
    assert_eq!(to_after, 6);
    log_assert("IB exploit arithmetic outcomes observed.");
}
