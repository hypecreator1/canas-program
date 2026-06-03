use anchor_lang::prelude::*;
use anchor_spl::token::{self, CloseAccount, Mint, Token, TokenAccount, Transfer};

// Deployed program id (mainnet) — pubkey of canas-keys/canas-keypair.json. MUST
// stay equal to the on-chain address and Anchor.toml [programs.mainnet], else every
// instruction fails with DeclaredProgramIdMismatch (0x1004) and a verified build
// would mismatch (declare_id is baked into the binary).
declare_id!("8e23bCyweHUVuiS3zhbhibuad5h6mXjwftTzPTjBomDq");

/// CANAS.NET — trustless diffusion-job escrow + provider staking + settlement.
///
/// Flow (matches the protocol):
///   1. `create_job`  — a requester locks USDC into a per-job escrow vault.
///   2. `assign_job`  — the (permissioned) scheduler/admin routes it to a staked provider.
///   3. `deliver_job` — the provider posts an attestation (perceptual hash) of the output.
///   4. `settle_job`  — on acceptance (requester now, or admin after the dispute
///                       window) the escrow splits ~provider/verifier/protocol and
///                       the vault + job account are closed (rent → requester).
///   `cancel_job` / `refund_job` return funds when a job is never picked up or never
///   delivered; `slash_provider` burns a misbehaving provider's bond into the treasury.
///
/// Money recovery (per the deploy guide): the program is deployed UPGRADEABLE
/// (never `--final`) so program/buffer rent is reclaimable via the CLI, and every
/// account has a `close_*` path that refunds its rent. No SOL is ever stranded.
///
/// Mints are wired AFTER deploy via `set_mints`, so the program can ship before
/// the $CNSNET token launches (USDC can be set immediately).
#[program]
pub mod canas {
    use super::*;

    // Job lifecycle status (Settled / Refunded / Slashed close the account, so
    // they need no persistent value).
    pub const STATUS_OPEN: u8 = 0;
    pub const STATUS_ASSIGNED: u8 = 1;
    pub const STATUS_DELIVERED: u8 = 2;

    const BPS_DENOM: u64 = 10_000;
    const REP_MAX: u32 = 10_000; // 100.00%
    const REP_START: u32 = 9_000;

    // ——— admin / config —————————————————————————————————————————————

    /// One-time global setup. `admin` (signer) becomes the scheduler/arbiter.
    /// Mints are left unset; wire them later with `set_mints`.
    pub fn initialize(
        ctx: Context<Initialize>,
        treasury: Pubkey,
        provider_bps: u16,
        verifier_bps: u16,
        protocol_bps: u16,
        dispute_window: i64,
    ) -> Result<()> {
        require!(
            provider_bps as u64 + verifier_bps as u64 + protocol_bps as u64 == BPS_DENOM,
            CanasError::BadSplit
        );
        require!(dispute_window >= 0, CanasError::BadWindow);
        let cfg = &mut ctx.accounts.config;
        cfg.admin = ctx.accounts.admin.key();
        cfg.treasury = treasury;
        cfg.usdc_mint = Pubkey::default();
        cfg.cnsnet_mint = Pubkey::default();
        cfg.provider_bps = provider_bps;
        cfg.verifier_bps = verifier_bps;
        cfg.protocol_bps = protocol_bps;
        cfg.dispute_window = dispute_window;
        cfg.job_count = 0;
        cfg.total_settled = 0;
        cfg.paused = false;
        cfg.bump = ctx.bumps.config;
        Ok(())
    }

    /// Wire the payment (USDC) and bond ($CNSNET) mints (admin only). Each mint
    /// can be set ONCE (default -> value) and is then locked, so it can never
    /// change underneath escrows/bonds that already depend on it. Pass the system
    /// address (Pubkey::default) for $CNSNET until that token launches, then call
    /// again to set it (USDC must stay the same).
    pub fn set_mints(ctx: Context<AdminOnly>, usdc_mint: Pubkey, cnsnet_mint: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require!(
            cfg.usdc_mint == Pubkey::default() || cfg.usdc_mint == usdc_mint,
            CanasError::MintLocked
        );
        require!(
            cfg.cnsnet_mint == Pubkey::default() || cfg.cnsnet_mint == cnsnet_mint,
            CanasError::MintLocked
        );
        cfg.usdc_mint = usdc_mint;
        cfg.cnsnet_mint = cnsnet_mint;
        Ok(())
    }

    /// Tune fee split, dispute window and treasury (admin only).
    pub fn set_params(
        ctx: Context<AdminOnly>,
        provider_bps: u16,
        verifier_bps: u16,
        protocol_bps: u16,
        dispute_window: i64,
        treasury: Pubkey,
    ) -> Result<()> {
        require!(
            provider_bps as u64 + verifier_bps as u64 + protocol_bps as u64 == BPS_DENOM,
            CanasError::BadSplit
        );
        require!(dispute_window >= 0, CanasError::BadWindow);
        let cfg = &mut ctx.accounts.config;
        cfg.provider_bps = provider_bps;
        cfg.verifier_bps = verifier_bps;
        cfg.protocol_bps = protocol_bps;
        cfg.dispute_window = dispute_window;
        cfg.treasury = treasury;
        Ok(())
    }

    /// Emergency pause / resume of new jobs (admin only).
    pub fn set_paused(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
        ctx.accounts.config.paused = paused;
        Ok(())
    }

    /// Hand admin to a new key (admin only).
    pub fn set_admin(ctx: Context<AdminOnly>, new_admin: Pubkey) -> Result<()> {
        ctx.accounts.config.admin = new_admin;
        Ok(())
    }

    /// Close the global Config and refund its rent to admin (decommission).
    pub fn close_config(_ctx: Context<CloseConfig>) -> Result<()> {
        Ok(())
    }

    // ——— providers (staking) ————————————————————————————————————————

    /// Register a provider and stake an initial $CNSNET bond into a program-owned
    /// bond vault. `payout` is the USDC token account that will receive earnings.
    pub fn register_provider(ctx: Context<RegisterProvider>, bond_amount: u64) -> Result<()> {
        require!(
            ctx.accounts.config.cnsnet_mint != Pubkey::default(),
            CanasError::MintNotSet
        );
        require!(bond_amount > 0, CanasError::ZeroAmount);
        require_keys_eq!(
            ctx.accounts.payout.mint,
            ctx.accounts.config.usdc_mint,
            CanasError::WrongMint
        );

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.provider_token.to_account_info(),
                    to: ctx.accounts.bond_vault.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            bond_amount,
        )?;

        let p = &mut ctx.accounts.provider;
        p.authority = ctx.accounts.authority.key();
        p.payout = ctx.accounts.payout.key();
        p.bond = bond_amount;
        p.reputation = REP_START;
        p.jobs_done = 0;
        p.total_earned = 0;
        p.in_flight = 0;
        p.active = true;
        p.bump = ctx.bumps.provider;

        emit!(ProviderRegistered {
            provider: p.key(),
            authority: p.authority,
            bond: bond_amount,
        });
        Ok(())
    }

    /// Add more $CNSNET to the bond.
    pub fn top_up_bond(ctx: Context<TopUpBond>, amount: u64) -> Result<()> {
        require!(amount > 0, CanasError::ZeroAmount);
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.provider_token.to_account_info(),
                    to: ctx.accounts.bond_vault.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
        )?;
        let p = &mut ctx.accounts.provider;
        p.bond = p.bond.checked_add(amount).ok_or(CanasError::Overflow)?;
        Ok(())
    }

    /// Close a provider: return the full remaining bond, close the bond vault and
    /// the Provider account (all rent → authority). Blocked while jobs are in-flight.
    pub fn close_provider(ctx: Context<CloseProvider>) -> Result<()> {
        require!(ctx.accounts.provider.in_flight == 0, CanasError::JobsInFlight);

        let authority_key = ctx.accounts.provider.authority;
        let bump = ctx.accounts.provider.bump;
        let remaining = ctx.accounts.bond_vault.amount;
        let seeds: &[&[u8]] = &[b"provider", authority_key.as_ref(), &[bump]];
        let signer = &[seeds];

        if remaining > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.bond_vault.to_account_info(),
                        to: ctx.accounts.provider_token.to_account_info(),
                        authority: ctx.accounts.provider.to_account_info(),
                    },
                    signer,
                ),
                remaining,
            )?;
        }
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.bond_vault.to_account_info(),
                destination: ctx.accounts.authority.to_account_info(),
                authority: ctx.accounts.provider.to_account_info(),
            },
            signer,
        ))?;
        Ok(())
    }

    /// Slash part of a provider's bond into the treasury (admin only) — the
    /// economic penalty for fabricated/substituted output.
    pub fn slash_provider(ctx: Context<SlashProvider>, amount: u64, reputation_penalty: u32) -> Result<()> {
        require!(amount > 0, CanasError::ZeroAmount);
        require!(amount <= ctx.accounts.bond_vault.amount, CanasError::InsufficientBond);

        let authority_key = ctx.accounts.provider.authority;
        let bump = ctx.accounts.provider.bump;
        let seeds: &[&[u8]] = &[b"provider", authority_key.as_ref(), &[bump]];
        let signer = &[seeds];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.bond_vault.to_account_info(),
                    to: ctx.accounts.slash_destination.to_account_info(),
                    authority: ctx.accounts.provider.to_account_info(),
                },
                signer,
            ),
            amount,
        )?;

        let p = &mut ctx.accounts.provider;
        p.bond = p.bond.saturating_sub(amount);
        p.reputation = p.reputation.saturating_sub(reputation_penalty);
        // a provider with no stake left can no longer be assigned new jobs
        if p.bond == 0 {
            p.active = false;
        }
        emit!(ProviderSlashed {
            provider: p.key(),
            amount,
            new_bond: p.bond,
        });
        Ok(())
    }

    // ——— jobs (escrow + settlement) ——————————————————————————————————

    /// Requester locks `amount` USDC into a per-job escrow vault.
    pub fn create_job(
        ctx: Context<CreateJob>,
        amount: u64,
        params_hash: [u8; 32],
        model_hash: [u8; 32],
    ) -> Result<()> {
        require!(!ctx.accounts.config.paused, CanasError::Paused);
        require!(
            ctx.accounts.config.usdc_mint != Pubkey::default(),
            CanasError::MintNotSet
        );
        require!(amount > 0, CanasError::ZeroAmount);

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.requester_token.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                    authority: ctx.accounts.requester.to_account_info(),
                },
            ),
            amount,
        )?;

        let nonce = ctx.accounts.config.job_count;
        let now = Clock::get()?.unix_timestamp;
        let job = &mut ctx.accounts.job;
        job.requester = ctx.accounts.requester.key();
        job.provider = Pubkey::default();
        job.mint = ctx.accounts.mint.key();
        job.amount = amount;
        job.nonce = nonce;
        job.params_hash = params_hash;
        job.model_hash = model_hash;
        job.output_phash = [0u8; 32];
        job.created_at = now;
        job.assigned_at = 0;
        job.delivered_at = 0;
        job.status = STATUS_OPEN;
        job.bump = ctx.bumps.job;

        let cfg = &mut ctx.accounts.config;
        cfg.job_count = cfg.job_count.checked_add(1).ok_or(CanasError::Overflow)?;

        emit!(JobCreated {
            job: job.key(),
            requester: job.requester,
            amount,
            nonce,
        });
        Ok(())
    }

    /// Scheduler/admin routes an open job to a staked, active provider.
    pub fn assign_job(ctx: Context<AssignJob>) -> Result<()> {
        require!(ctx.accounts.job.status == STATUS_OPEN, CanasError::BadStatus);
        require!(ctx.accounts.provider.active, CanasError::ProviderInactive);

        ctx.accounts.job.provider = ctx.accounts.provider.key();
        ctx.accounts.job.status = STATUS_ASSIGNED;
        ctx.accounts.job.assigned_at = Clock::get()?.unix_timestamp;
        let p = &mut ctx.accounts.provider;
        p.in_flight = p.in_flight.checked_add(1).ok_or(CanasError::Overflow)?;

        emit!(JobAssigned {
            job: ctx.accounts.job.key(),
            provider: ctx.accounts.provider.key(),
        });
        Ok(())
    }

    /// Provider posts the perceptual-hash attestation of its output.
    pub fn deliver_job(ctx: Context<DeliverJob>, output_phash: [u8; 32]) -> Result<()> {
        require!(ctx.accounts.job.status == STATUS_ASSIGNED, CanasError::BadStatus);
        let job = &mut ctx.accounts.job;
        job.output_phash = output_phash;
        job.delivered_at = Clock::get()?.unix_timestamp;
        job.status = STATUS_DELIVERED;
        emit!(JobDelivered {
            job: job.key(),
            output_phash,
        });
        Ok(())
    }

    /// Settle a delivered job: split the escrow provider / verifier / protocol,
    /// then close the vault and job (rent → requester). Callable by the requester
    /// (accept) immediately, or by admin once the dispute window has elapsed
    /// (optimistic acceptance).
    pub fn settle_job(ctx: Context<SettleJob>) -> Result<()> {
        // read scalars up front, before the CPIs that borrow account infos
        let amount = ctx.accounts.job.amount;
        let requester_key = ctx.accounts.job.requester;
        let nonce = ctx.accounts.job.nonce;
        let job_bump = ctx.accounts.job.bump;
        let delivered_at = ctx.accounts.job.delivered_at;
        let admin = ctx.accounts.config.admin;
        let window = ctx.accounts.config.dispute_window;
        let provider_bps = ctx.accounts.config.provider_bps as u64;
        let verifier_bps = ctx.accounts.config.verifier_bps as u64;
        let signer_key = ctx.accounts.authority.key();

        require!(ctx.accounts.job.status == STATUS_DELIVERED, CanasError::BadStatus);
        let is_requester = signer_key == requester_key;
        let is_admin = signer_key == admin;
        require!(is_requester || is_admin, CanasError::Unauthorized);
        if is_admin && !is_requester {
            let now = Clock::get()?.unix_timestamp;
            require!(now >= delivered_at + window, CanasError::WindowNotElapsed);
        }

        // The split ratio is computed from the job amount, but the actual
        // transfers are driven by the LIVE vault balance so the vault is ALWAYS
        // fully drained — a stray/grief token donation to the deterministic vault
        // PDA can never leave a residual that would make close_account fail and
        // strand the escrow. The provider gets its intended share; everything else
        // (verifier + protocol + any donation) goes to the protocol treasury,
        // which pays verifiers off-chain. This also removes the caller-chosen
        // verifier destination, so the verifier cut can't be self-dealt.
        let provider_amt = (amount as u128 * provider_bps as u128 / BPS_DENOM as u128) as u64;
        let verifier_amt = (amount as u128 * verifier_bps as u128 / BPS_DENOM as u128) as u64;
        let vault_balance = ctx.accounts.vault.amount;
        require!(vault_balance >= provider_amt, CanasError::Overflow);
        let rest = vault_balance - provider_amt; // verifier + protocol (+ any donation)
        let protocol_amt = rest.saturating_sub(verifier_amt); // for the event only

        let seeds: &[&[u8]] = &[b"job", requester_key.as_ref(), &nonce.to_le_bytes(), &[job_bump]];
        let signer = &[seeds];

        if provider_amt > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.vault.to_account_info(),
                        to: ctx.accounts.provider_payout.to_account_info(),
                        authority: ctx.accounts.job.to_account_info(),
                    },
                    signer,
                ),
                provider_amt,
            )?;
        }
        if rest > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.vault.to_account_info(),
                        to: ctx.accounts.treasury.to_account_info(),
                        authority: ctx.accounts.job.to_account_info(),
                    },
                    signer,
                ),
                rest,
            )?;
        }

        // close the now-empty vault, rent → requester
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.vault.to_account_info(),
                destination: ctx.accounts.requester.to_account_info(),
                authority: ctx.accounts.job.to_account_info(),
            },
            signer,
        ))?;

        // provider accounting + reputation nudge
        let p = &mut ctx.accounts.provider;
        p.jobs_done = p.jobs_done.checked_add(1).ok_or(CanasError::Overflow)?;
        p.total_earned = p.total_earned.checked_add(provider_amt).ok_or(CanasError::Overflow)?;
        p.in_flight = p.in_flight.saturating_sub(1);
        p.reputation = p.reputation.saturating_add(2).min(REP_MAX);

        let cfg = &mut ctx.accounts.config;
        cfg.total_settled = cfg.total_settled.checked_add(amount as u128).ok_or(CanasError::Overflow)?;

        emit!(JobSettled {
            job: ctx.accounts.job.key(),
            provider: ctx.accounts.provider.key(),
            provider_amt,
            verifier_amt,
            protocol_amt,
        });
        Ok(())
        // `job` is closed by the `close = requester` constraint after the handler.
    }

    /// Cancel an OPEN (never-assigned) job and refund the full escrow to the
    /// requester. Callable by the requester, or by admin.
    pub fn cancel_job(ctx: Context<CancelJob>) -> Result<()> {
        // refund the LIVE vault balance so a grief-donation can't strand it / block close
        let amount = ctx.accounts.vault.amount;
        let requester_key = ctx.accounts.job.requester;
        let nonce = ctx.accounts.job.nonce;
        let job_bump = ctx.accounts.job.bump;
        let signer_key = ctx.accounts.authority.key();

        require!(ctx.accounts.job.status == STATUS_OPEN, CanasError::BadStatus);
        require!(
            signer_key == requester_key || signer_key == ctx.accounts.config.admin,
            CanasError::Unauthorized
        );

        let seeds: &[&[u8]] = &[b"job", requester_key.as_ref(), &nonce.to_le_bytes(), &[job_bump]];
        let signer = &[seeds];

        if amount > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.vault.to_account_info(),
                        to: ctx.accounts.requester_token.to_account_info(),
                        authority: ctx.accounts.job.to_account_info(),
                    },
                    signer,
                ),
                amount,
            )?;
        }
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.vault.to_account_info(),
                destination: ctx.accounts.requester.to_account_info(),
                authority: ctx.accounts.job.to_account_info(),
            },
            signer,
        ))?;
        emit!(JobRefunded {
            job: ctx.accounts.job.key(),
            amount,
        });
        Ok(())
    }

    /// Refund an assigned-but-failed or disputed job to the requester and close it.
    /// - the requester may call once an assigned job has passed the dispute window
    ///   without acceptable delivery;
    /// - admin may call at any time to resolve a dispute in the requester's favour.
    /// The provider's in-flight counter is released and reputation dinged.
    pub fn refund_job(ctx: Context<RefundJob>, reputation_penalty: u32) -> Result<()> {
        // refund the LIVE vault balance so a grief-donation can't strand it / block close
        let amount = ctx.accounts.vault.amount;
        let requester_key = ctx.accounts.job.requester;
        let nonce = ctx.accounts.job.nonce;
        let job_bump = ctx.accounts.job.bump;
        let status = ctx.accounts.job.status;
        let assigned_at = ctx.accounts.job.assigned_at;
        let window = ctx.accounts.config.dispute_window;
        let admin = ctx.accounts.config.admin;
        let signer_key = ctx.accounts.authority.key();

        require!(
            status == STATUS_ASSIGNED || status == STATUS_DELIVERED,
            CanasError::BadStatus
        );
        let is_admin = signer_key == admin;
        let is_requester = signer_key == requester_key;
        require!(is_admin || is_requester, CanasError::Unauthorized);
        // a requester can only force a refund on a non-delivered job after the window;
        // delivered jobs and early refunds require the admin arbiter.
        if !is_admin {
            require!(status == STATUS_ASSIGNED, CanasError::Unauthorized);
            let now = Clock::get()?.unix_timestamp;
            require!(now >= assigned_at + window, CanasError::WindowNotElapsed);
        }

        let seeds: &[&[u8]] = &[b"job", requester_key.as_ref(), &nonce.to_le_bytes(), &[job_bump]];
        let signer = &[seeds];

        if amount > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.vault.to_account_info(),
                        to: ctx.accounts.requester_token.to_account_info(),
                        authority: ctx.accounts.job.to_account_info(),
                    },
                    signer,
                ),
                amount,
            )?;
        }
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.vault.to_account_info(),
                destination: ctx.accounts.requester.to_account_info(),
                authority: ctx.accounts.job.to_account_info(),
            },
            signer,
        ))?;

        let p = &mut ctx.accounts.provider;
        p.in_flight = p.in_flight.saturating_sub(1);
        p.reputation = p.reputation.saturating_sub(reputation_penalty);

        emit!(JobRefunded {
            job: ctx.accounts.job.key(),
            amount,
        });
        Ok(())
    }
}

// ===========================================================================
// Accounts
// ===========================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = admin, space = 8 + Config::SIZE, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseConfig<'info> {
    #[account(mut, close = admin, seeds = [b"config"], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct RegisterProvider<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(address = config.cnsnet_mint @ CanasError::WrongMint)]
    pub cnsnet_mint: Account<'info, Mint>,

    /// USDC token account that will receive this provider's earnings.
    #[account(token::mint = config.usdc_mint)]
    pub payout: Account<'info, TokenAccount>,

    #[account(
        init,
        payer = authority,
        space = 8 + Provider::SIZE,
        seeds = [b"provider", authority.key().as_ref()],
        bump
    )]
    pub provider: Account<'info, Provider>,

    #[account(
        init,
        payer = authority,
        seeds = [b"bond", provider.key().as_ref()],
        bump,
        token::mint = cnsnet_mint,
        token::authority = provider,
    )]
    pub bond_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        token::mint = cnsnet_mint,
        token::authority = authority,
    )]
    pub provider_token: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct TopUpBond<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"provider", authority.key().as_ref()],
        bump = provider.bump,
        has_one = authority,
    )]
    pub provider: Account<'info, Provider>,
    #[account(mut, seeds = [b"bond", provider.key().as_ref()], bump)]
    pub bond_vault: Account<'info, TokenAccount>,
    #[account(mut, token::authority = authority, constraint = provider_token.mint == bond_vault.mint @ CanasError::WrongMint)]
    pub provider_token: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CloseProvider<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        mut,
        close = authority,
        seeds = [b"provider", authority.key().as_ref()],
        bump = provider.bump,
        has_one = authority,
    )]
    pub provider: Account<'info, Provider>,
    #[account(mut, seeds = [b"bond", provider.key().as_ref()], bump)]
    pub bond_vault: Account<'info, TokenAccount>,
    #[account(mut, token::authority = authority, constraint = provider_token.mint == bond_vault.mint @ CanasError::WrongMint)]
    pub provider_token: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct SlashProvider<'info> {
    #[account(seeds = [b"config"], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
    #[account(
        mut,
        seeds = [b"provider", provider.authority.as_ref()],
        bump = provider.bump,
    )]
    pub provider: Account<'info, Provider>,
    #[account(mut, seeds = [b"bond", provider.key().as_ref()], bump)]
    pub bond_vault: Account<'info, TokenAccount>,
    /// Where the slashed bond goes (a $CNSNET token account, e.g. the treasury).
    #[account(mut, constraint = slash_destination.mint == bond_vault.mint @ CanasError::WrongMint)]
    pub slash_destination: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CreateJob<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub requester: Signer<'info>,

    #[account(address = config.usdc_mint @ CanasError::WrongMint)]
    pub mint: Account<'info, Mint>,

    #[account(
        init,
        payer = requester,
        space = 8 + Job::SIZE,
        seeds = [b"job", requester.key().as_ref(), &config.job_count.to_le_bytes()],
        bump
    )]
    pub job: Account<'info, Job>,

    #[account(
        init,
        payer = requester,
        seeds = [b"vault", job.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = job,
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(mut, token::mint = mint, token::authority = requester)]
    pub requester_token: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct AssignJob<'info> {
    #[account(seeds = [b"config"], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
    #[account(
        mut,
        seeds = [b"job", job.requester.as_ref(), &job.nonce.to_le_bytes()],
        bump = job.bump,
    )]
    pub job: Account<'info, Job>,
    #[account(
        mut,
        seeds = [b"provider", provider.authority.as_ref()],
        bump = provider.bump,
    )]
    pub provider: Account<'info, Provider>,
}

#[derive(Accounts)]
pub struct DeliverJob<'info> {
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"job", job.requester.as_ref(), &job.nonce.to_le_bytes()],
        bump = job.bump,
        constraint = job.provider == provider.key() @ CanasError::Unauthorized,
    )]
    pub job: Account<'info, Job>,
    #[account(
        seeds = [b"provider", authority.key().as_ref()],
        bump = provider.bump,
        has_one = authority,
    )]
    pub provider: Account<'info, Provider>,
}

#[derive(Accounts)]
pub struct SettleJob<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    /// requester (accept) or admin (after window). Validated in the handler.
    pub authority: Signer<'info>,

    /// CHECK: rent destination for the closed vault/job; must be the job's requester.
    #[account(mut, address = job.requester)]
    pub requester: UncheckedAccount<'info>,

    #[account(
        mut,
        close = requester,
        seeds = [b"job", job.requester.as_ref(), &job.nonce.to_le_bytes()],
        bump = job.bump,
        constraint = job.provider == provider.key() @ CanasError::Unauthorized,
    )]
    pub job: Account<'info, Job>,

    #[account(mut, seeds = [b"vault", job.key().as_ref()], bump)]
    pub vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [b"provider", provider.authority.as_ref()],
        bump = provider.bump,
    )]
    pub provider: Account<'info, Provider>,

    #[account(mut, address = provider.payout @ CanasError::WrongDestination,
              constraint = provider_payout.mint == config.usdc_mint @ CanasError::WrongMint)]
    pub provider_payout: Account<'info, TokenAccount>,

    /// Protocol treasury — receives verifier + protocol shares (verifiers are paid
    /// off-chain from it in v1, so the cut can't be diverted at settle time).
    #[account(mut, address = config.treasury @ CanasError::WrongDestination,
              constraint = treasury.mint == config.usdc_mint @ CanasError::WrongMint)]
    pub treasury: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CancelJob<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    pub authority: Signer<'info>,

    /// CHECK: rent destination; must be the job's requester.
    #[account(mut, address = job.requester)]
    pub requester: UncheckedAccount<'info>,

    #[account(
        mut,
        close = requester,
        seeds = [b"job", job.requester.as_ref(), &job.nonce.to_le_bytes()],
        bump = job.bump,
    )]
    pub job: Account<'info, Job>,

    #[account(mut, seeds = [b"vault", job.key().as_ref()], bump)]
    pub vault: Account<'info, TokenAccount>,

    #[account(mut, constraint = requester_token.mint == job.mint @ CanasError::WrongMint,
              constraint = requester_token.owner == job.requester @ CanasError::WrongDestination)]
    pub requester_token: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct RefundJob<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    pub authority: Signer<'info>,

    /// CHECK: rent destination; must be the job's requester.
    #[account(mut, address = job.requester)]
    pub requester: UncheckedAccount<'info>,

    #[account(
        mut,
        close = requester,
        seeds = [b"job", job.requester.as_ref(), &job.nonce.to_le_bytes()],
        bump = job.bump,
        constraint = job.provider == provider.key() @ CanasError::Unauthorized,
    )]
    pub job: Account<'info, Job>,

    #[account(mut, seeds = [b"vault", job.key().as_ref()], bump)]
    pub vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [b"provider", provider.authority.as_ref()],
        bump = provider.bump,
    )]
    pub provider: Account<'info, Provider>,

    #[account(mut, constraint = requester_token.mint == job.mint @ CanasError::WrongMint,
              constraint = requester_token.owner == job.requester @ CanasError::WrongDestination)]
    pub requester_token: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

// ===========================================================================
// State
// ===========================================================================

#[account]
pub struct Config {
    pub admin: Pubkey,         // 32
    pub treasury: Pubkey,      // 32 (protocol USDC token account)
    pub usdc_mint: Pubkey,     // 32 (zero until set_mints)
    pub cnsnet_mint: Pubkey,   // 32 (zero until set_mints)
    pub provider_bps: u16,     // 2
    pub verifier_bps: u16,     // 2
    pub protocol_bps: u16,     // 2
    pub dispute_window: i64,   // 8
    pub job_count: u64,        // 8
    pub total_settled: u128,   // 16
    pub paused: bool,          // 1
    pub bump: u8,              // 1
}
impl Config {
    pub const SIZE: usize = 32 * 4 + 2 * 3 + 8 + 8 + 16 + 1 + 1;
}

#[account]
pub struct Provider {
    pub authority: Pubkey,   // 32
    pub payout: Pubkey,      // 32 (USDC token account)
    pub bond: u64,           // 8
    pub reputation: u32,     // 4 (0..10000 = 0..100.00%)
    pub jobs_done: u64,      // 8
    pub total_earned: u64,   // 8
    pub in_flight: u32,      // 4
    pub active: bool,        // 1
    pub bump: u8,            // 1
}
impl Provider {
    pub const SIZE: usize = 32 + 32 + 8 + 4 + 8 + 8 + 4 + 1 + 1;
}

#[account]
pub struct Job {
    pub requester: Pubkey,      // 32
    pub provider: Pubkey,       // 32 (Provider PDA; default until assigned)
    pub mint: Pubkey,           // 32
    pub amount: u64,            // 8
    pub nonce: u64,             // 8
    pub params_hash: [u8; 32],  // 32
    pub model_hash: [u8; 32],   // 32
    pub output_phash: [u8; 32], // 32
    pub created_at: i64,        // 8
    pub assigned_at: i64,       // 8
    pub delivered_at: i64,      // 8
    pub status: u8,             // 1
    pub bump: u8,               // 1
}
impl Job {
    pub const SIZE: usize = 32 * 3 + 8 + 8 + 32 * 3 + 8 + 8 + 8 + 1 + 1;
}

// ===========================================================================
// Events
// ===========================================================================

#[event]
pub struct ProviderRegistered {
    pub provider: Pubkey,
    pub authority: Pubkey,
    pub bond: u64,
}
#[event]
pub struct ProviderSlashed {
    pub provider: Pubkey,
    pub amount: u64,
    pub new_bond: u64,
}
#[event]
pub struct JobCreated {
    pub job: Pubkey,
    pub requester: Pubkey,
    pub amount: u64,
    pub nonce: u64,
}
#[event]
pub struct JobAssigned {
    pub job: Pubkey,
    pub provider: Pubkey,
}
#[event]
pub struct JobDelivered {
    pub job: Pubkey,
    pub output_phash: [u8; 32],
}
#[event]
pub struct JobSettled {
    pub job: Pubkey,
    pub provider: Pubkey,
    pub provider_amt: u64,
    pub verifier_amt: u64,
    pub protocol_amt: u64,
}
#[event]
pub struct JobRefunded {
    pub job: Pubkey,
    pub amount: u64,
}

// ===========================================================================
// Errors
// ===========================================================================

#[error_code]
pub enum CanasError {
    #[msg("fee split must sum to 10000 bps")]
    BadSplit,
    #[msg("dispute window must be non-negative")]
    BadWindow,
    #[msg("new jobs are paused")]
    Paused,
    #[msg("mint not set yet")]
    MintNotSet,
    #[msg("wrong mint")]
    WrongMint,
    #[msg("wrong token destination")]
    WrongDestination,
    #[msg("amount must be greater than zero")]
    ZeroAmount,
    #[msg("provider has jobs in flight")]
    JobsInFlight,
    #[msg("provider is not active")]
    ProviderInactive,
    #[msg("insufficient bond")]
    InsufficientBond,
    #[msg("invalid job status for this action")]
    BadStatus,
    #[msg("unauthorized")]
    Unauthorized,
    #[msg("dispute window has not elapsed")]
    WindowNotElapsed,
    #[msg("mint already set and locked")]
    MintLocked,
    #[msg("arithmetic overflow")]
    Overflow,
}
