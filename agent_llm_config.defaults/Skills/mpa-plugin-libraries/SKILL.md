---
name: mpa-plugin-libraries
description: Function index for a plugin entrypoint that imports DeFi or technical analysis. Use while writing extension code. Names the package subpath and the export to call.
---

# Plugin libraries

Load this before writing an entrypoint that imports DeFi or market data. Call the export names below. Do not call `ctm_*` tools, `load_defi_protocol`, or `@continuumdao/continuum-node-sdk` from the entrypoint. Return the function result. A build function returns an unsigned payload. The agent opens the sign request.

The DeFi list is generated from the tool catalog. `npm test` in ctm-mpc-defi fails when a protocol was added or updated and this list was not regenerated. `npm run build` writes it again.

## Market data

`@continuumdao/ctm-market-data`. Name only the subpath the entrypoint imports.

### `ta`

`importMarket('ta')`. `marketModules`: `ta`.

- `listIndicatorCatalog()` — every indicator id, its aliases, and the input shape it expects.
- `resolveIndicatorId(name)` — canonical id for a name or alias.
- `suggestIndicator(name)` — nearest id when the name is not exact.
- `calculateTechnicalIndicator({ indicator, params, input })` — run one indicator. `input.candles` is `{ open, high, low, close, volume? }[]`, or pass `input.close` as a number array. Period indicators take `params.period`.

Call `listIndicatorCatalog` for the indicator list. Do not hard-code every id into the plugin.

### `ohlcv`

`importMarket('ohlcv')`. `marketModules`: `ohlcv`.

- `finalizeOhlcvFetch(fetchPayload)` — check candle integrity and return `{ kind, bars, fingerprint }`. Pass a DeFi OHLCV result or `{ bars }`. Return that object. Do not build a chart. The agent passes it as `fetchResult` to `prepare_chart_from_rows`.
- `normalizeOhlcvRow` / `extractOhlcvBarsFromUnknown` — turn a fetch result into rows.
- `analyzeMovingAverages({ rows, maType, fastPeriod, slowPeriod })` — SMA or EMA cross. `maType` is `sma` or `ema`. Omit the periods for SMA 50 and 200. Result `analysis.crossoverState` is `bullish`, `bearish`, or `none`.

### `trade-ideas`

`importMarket('trade-ideas')`. `marketModules`: `trade-ideas`.

- `tradeIdeaFromAnalyzeOutput(toolName, analysis)` — entry, target, and invalidation from an analyze result. This does not build a transaction. The agent calls `build_trade_from_*` and opens the sign request.

## DeFi

`@continuumdao/ctm-mpc-defi`. Put each import path in `defiModules`. Add `core` when the protocol file imports shared helpers. One protocol is enough unless the operator asked for more.

Each line is `exportName` — what it does. Names in parentheses are the inputs the call needs besides a KeyGen. The plugin does not have a management key.

### aave-v4

`defiModules`: `protocols/evm/aave-v4`

- `aaveV4FetchMarketsSummary` — List Aave v4 hub reserves on a chain with live supply/borrow APY, liquidity, and collateral factor. Use this (not web search) to compare lending rates or pick… (chainId)
- `aaveV4FetchMarketSummary` — One Aave v4 reserve (or the same underlying across hubs) with supply/borrow APY and liquidity. Copy underlying + marketId for deposit/borrow/repay. Tickers OK… (chainId, underlying)
- `aaveV4FetchMerklRewardsSummary` — Wallet-wide Merkl claimables for this address on a chain (not Aave-only). Pass keyGenId or user. Other venues’ campaigns can appear. rEUL is omitted. Follow wi… (chainId)
- `aaveV4FetchStockMarketsSummary` — Coinbase tokenized stocks (bStocks) on the Aave v4 Coinbase Stocks hub, Base chainId 8453 by default. Equities (AAPLc, NVDAc, …) are collateral-only; USDC is t…
- `buildEvmMultisignBodyAaveV4DepositBatch` — Build Aave v4 Spoke supply/deposit batch (wrap native, approve, supply). Base bStocks: marketId bstocks and underlying ticker (AAPLc) or address. Builds the un… (chainId, underlying, amountHuman)
- `buildEvmMultisignBodyAaveV4MerklDistributorClaim` — Build wallet-wide Merkl Distributor.claim. Pass keyGenId + chainId; server fetches proofs. Optional claimData override. Builds the unsigned batch, signs the ma… (chainId)
- `buildEvmMultisignBodyAaveV4SpokeBorrow` — Build Aave v4 Spoke borrow; underlying is the debt asset (USDC on bstocks). Equities are collateral-only. collateralUnderlying may be a bStock ticker (AAPLc).… (chainId, underlying, amountHuman)
- `buildEvmMultisignBodyAaveV4SpokeRepay` — Build Aave v4 Spoke repay (approve if needed + repay). Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { request… (chainId, underlying, amountHuman)
- `buildEvmMultisignBodyAaveV4SpokeWithdraw` — Build Aave v4 Spoke withdraw; health-factor preview when user has borrow debt. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRe… (chainId, underlying, amountHuman)

### aerodrome

`defiModules`: `protocols/evm/aerodrome`

- `aerodromeDiscoverPoolsSummary` — Find Aero v2 + Slipstream pools for one token (optional tokenOut, default USDC) via factory getPool. Protocol id stays aerodrome. Chains: Base 8453 (default),… (chainId, token)
- `aerodromeFetchLpYieldsSummary` — Fee tier + AERO emissions APR for the same ~100 important Aero pairs on Base (protocol id aerodrome). feeApr is null (Sugar has no volume). Other launch chains… (chainId)
- `aerodromeFetchPoolsSummary` — At most ~100 important Aero pools from the Base LpSugar index (ETH/WETH, USDC, AERO, major stables; TVL-ranked). Other launch chains have no Sugar index — use… (chainId)
- `aerodromeFetchPositionsSummary` — KeyGen Aerodrome positions (same picker as the Multi-Sign Rewards tab). Each row has label, kind (vAMM/sAMM/CL), gauge, stakedInGauge, claimFees.pool, and clai… (chainId)
- `aerodromeFetchStockLpYieldsSummary` — Coinbase B20 stock LP yields on Base only (AAPLc/USDC, …). Separate from main-pair fetch_lp_yields. Trading stocks is not this list. (chainId)
- `aerodromeQuote` — Quote an Aero swap. Protocol id stays aerodrome. chainId is Base 8453 by default, or Ethereum 1, OP Mainnet 10, Arbitrum 42161, Robinhood 4663, Arc 5042, Ink 5… (chainId, tokenIn, tokenOut, amountHuman)
- `aerodromeQuoteAddLiquidity` — Quote an Aero deposit (same as the Liquidity tab). One-sided: pass amountAHuman or amountBHuman; the other side comes from the current vAMM/sAMM reserves or Sl… (chainId, tokenA, tokenB)
- `aerodromeQuoteClDeposit` — Quote a Slipstream CL deposit (SugarHelper estimate when one side is omitted). token0/token1 accept tickers (AAPLc, USDC, ETH). Use when quote_add_liquidity re… (chainId, token0, token1, tickSpacing, tickLower, tickUpper, sqrtPriceX96)
- `buildEvmMultisignBodyAerodromeAddLiquidityBatch` — Submit multiSignRequest to add basic vAMM/sAMM liquidity (approve + addLiquidity / addLiquidityETH). One-sided amounts OK. Refuses empty/unseedable pairs (ETH/… (chainId, tokenA, tokenB, slippagePercent)
- `buildEvmMultisignBodyAerodromeClaimEmissionsBatch` — Claim gauge emissions in AERO (dialog: “Emissions from the gauge in AERO”). Pass claimEmissions from ctm_aerodrome_fetch_positions (gauge; CL staked also needs… (chainId, gauge)
- `buildEvmMultisignBodyAerodromeClaimFeesBatch` — Claim unstaked fees from the pool (dialog: “Fees from the pool”). Pass claimFees.pool from ctm_aerodrome_fetch_positions — not the gauge. Activate aerodrome:re… (chainId, pool)
- `buildEvmMultisignBodyAerodromeClBurnBatch` — Submit multiSignRequest to burn an empty Slipstream position NFT. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Return… (chainId, tokenId)
- `buildEvmMultisignBodyAerodromeClCollectBatch` — Collect Slipstream NFT fees via NFPM.collect. Pass the position id from fetch_positions (kind:cl). Activate aerodrome:rewards first. Builds the unsigned batch,… (chainId, tokenId)
- `buildEvmMultisignBodyAerodromeClDecreaseBatch` — Submit multiSignRequest to decrease Slipstream liquidity. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requ… (chainId, tokenId, liquidity)
- `buildEvmMultisignBodyAerodromeClIncreaseBatch` — Submit multiSignRequest to increase Slipstream liquidity. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requ… (chainId, tokenId, token0, token1, amount0Wei, amount1Wei, slippagePercent)
- `buildEvmMultisignBodyAerodromeClMintBatch` — Submit multiSignRequest to mint a Slipstream concentrated liquidity NFT. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest.… (chainId, token0, token1, tickSpacing, tickLower, tickUpper, sqrtPriceX96, slippagePercent)
- `buildEvmMultisignBodyAerodromeGaugeStakeBatch` — Submit multiSignRequest to stake basic LP tokens or a Slipstream NFT in a gauge. Builds the unsigned batch, signs the management envelope, and POSTs /multiSign… (chainId, gauge)
- `buildEvmMultisignBodyAerodromeGaugeUnstakeBatch` — Submit multiSignRequest to unstake from an Aerodrome gauge. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { re… (chainId, gauge)
- `buildEvmMultisignBodyAerodromeRemoveLiquidityBatch` — Submit multiSignRequest to remove basic-pool liquidity. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { reques… (chainId, tokenA, tokenB, lpToken, liquidityHuman)
- `buildEvmMultisignBodyAerodromeSwapBatch` — Create and submit mpc-auth multiSignRequest for an Aero swap (optional ERC-20 approve + Metarouter execute for v2, or Slipstream SwapRouter for a single CL hop… (chainId, tokenIn, tokenOut, amountHuman, slippagePercent)

### arcus

`defiModules`: `protocols/evm/arcus`

- `arcusFetchAccountSummary` — Arcus perp account summary (equity, collateral). (executorAddress)
- `arcusFetchMarketSnapshotSummary` — Live mid price plus recent perp OHLCV candles.
- `arcusFetchMarketsSummary` — List Arcus perp markets on Robinhood Chain (4663). Crypto, equities, commodities.
- `arcusFetchOhlcvSummary` — OHLCV for Arcus perps (api.arcus.xyz). Returns HL-shaped { ohlcv: { market, interval, candles } } for chart/analysis binding. Use for perp charts only — spot u…
- `arcusFetchOpenContextSummary` — Account, positions, orders, API keys, per-market leverages, and optional activeAsset leverage for a market. (executorAddress)
- `arcusFetchOpenOrdersSummary` — Pending Arcus perp orders. (executorAddress)
- `arcusFetchPositionsSummary` — Open Arcus perp positions. (executorAddress)
- `arcusSearchMarketsSummary` — Search Arcus perp markets by ticker or name. (query)
- `arcusSpotFetchBalancesSummary` — On-chain Stock Token ERC20 balances for executor on 4663. (executorAddress)
- `arcusSpotFetchMarketsSummary` — Arcus spot Stock Token catalog (ticker, contract address, logo).
- `arcusSpotFetchOhlcvSummary` — OHLCV for Arcus spot Stock Tokens (indexer.spot.arcus.xyz). Use for spot charts — not perp ctm_arcus_fetch_ohlcv.
- `arcusSpotSearchMarketsSummary` — Search Arcus spot Stock Tokens. (query)
- `buildArcusWithdrawMultisignBody` — Withdraw USDG collateral from Arcus to the signing wallet (EIP-712 + POST /v1/withdraw). product=perp or spot. Min $1. Async — refresh with ctm_arcus_fetch_acc… (chainId, usdHuman)
- `buildEvmMultisignBodyArcusCancelOrderBatch` — Cancel Arcus perp order (Ed25519 payload sign). Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on… (chainId, secp256k1KeyGenId, ed25519KeyGenId, market, orderId)
- `buildEvmMultisignBodyArcusCloseBatch` — Close Arcus perp position with IoC reduce-only limit (Ed25519 payload sign). Inverts side from isLong. Fetch positions via fetch_open_context. Builds the unsig… (chainId, secp256k1KeyGenId, ed25519KeyGenId, market, limitPxHuman, szHuman)
- `buildEvmMultisignBodyArcusCreateApiKeyBatch` — Register Arcus Ed25519 API key. Requires paired KeyGens (same GroupId): secp256k1KeyGenId for personal_sign + ed25519KeyGenId pubkey. No useCustomGas. Builds t… (chainId, secp256k1KeyGenId, ed25519KeyGenId, ed25519PubKeyHex)
- `buildEvmMultisignBodyArcusDepositBatch` — Deposit USDG on Robinhood Chain (4663) into Arcus collateral via approve + initiateDeposit. product=perp (accountIndex 0) or spot (accountIndex 1). Requires re… (chainId, usdHuman)
- `buildEvmMultisignBodyArcusPlaceOrderBatch` — Arcus perp limit order with optional TP/SL bracket (Ed25519 payload sign). Uses account leverage already set on Arcus (see fetch_open_context.activeAsset). ed2… (chainId, secp256k1KeyGenId, ed25519KeyGenId, market, limitPxHuman, szHuman)
- `buildEvmMultisignBodyArcusSetLeverageBatch` — Set Arcus perp leverage for a market (Scheme 2 Ed25519 → POST /v1/setLeverage). Call before place_order when leverage must change. Max leverage = floor(1 / ini… (chainId, secp256k1KeyGenId, ed25519KeyGenId, market, leverage)
- `buildEvmMultisignBodyArcusSpotRfqBatch` — Arcus spot Stock Token RFQ buy/sell. Post-fill: offer Add ERC20 with tokenContractAddress from delivery. Builds the unsigned batch, signs the management envelo… (chainId, secp256k1KeyGenId, ed25519KeyGenId, ticker, sizeHuman)

### circle-cctp

`defiModules`: `protocols/evm/circle-cctp`

- `buildEvmMultisignBodyCctpBurnBatchFromMcp` — Create and submit mpc-auth multiSignRequest for CCTP Forwarding Service USDC transfer (approve + depositForBurnWithHook on source chain). Re-quotes Iris and se… (chainId, destChainId, transferAmountHuman)
- `cctpFetchBurnFeesForRoute` — Quote Circle Iris CCTP fees (?forward=true). maxFee = forwardFee[tier] + protocol fee (minimumFee bps of transferAmountHuman). Pass transferAmountHuman before… (sourceChainId, destChainId)
- `cctpFetchSupportedRoutes` — List supported Circle CCTP V2 Forwarding Service routes (EVM source → destination pairs on mainnet or testnet). Read-only.
- `cctpFetchTransferStatus` — Poll Circle Iris for CCTP message/attestation status after source-chain burn Execute. Read-only. (sourceChainId, sourceDomain, burnTxHash)
- `cctpFetchUsdcBalance` — Read MPC wallet USDC balance on a CCTP source chain. Read-only. (chainId)

### compound-v3

`defiModules`: `protocols/evm/compound-v3`

- `buildEvmMultisignBodyCompoundV3Bulker` — Optional combined Bulker.invoke (supply + borrow, claim + withdraw, native via Bulker). ETH wrap still works without this tool. Builds the unsigned batch, sign… (chainId, comet, steps)
- `buildEvmMultisignBodyCompoundV3ClaimRewards` — Claim COMP / reward token from the market Rewards contract. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { re… (chainId, comet)
- `buildEvmMultisignBodyCompoundV3Repay` — Repay Comet base debt by supplying the base asset (same as supply of base while borrowed). Builds the unsigned batch, signs the management envelope, and POSTs… (chainId, comet, asset, amountHuman)
- `buildEvmMultisignBodyCompoundV3Supply` — Supply base (earn or repay) or collateral to a Comet proxy. Native ETH always wraps via WETH.deposit even when useBulker is false. Builds the unsigned batch, s… (chainId, comet, asset, amountHuman)
- `buildEvmMultisignBodyCompoundV3Withdraw` — Withdraw collateral or base from a Comet. Withdraw of base while undercollateralized borrows. Native ETH always unwraps via WETH.withdraw. Builds the unsigned… (chainId, comet, asset, amountHuman)
- `compoundV3FetchAccountSummary` — User position on a Comet: base supplied, base borrowed, each collateral, isBorrowCollateralized, isLiquidatable, claimable rewards. (chainId, comet, account)
- `compoundV3FetchMarketsSummary` — List Compound III Comet markets on a chain. Each market has one borrowable base and a collateral list — use this (not web search) to answer what you can borrow… (chainId)
- `compoundV3FetchMarketSummary` — One Comet: collateral list (what backs a borrow), collateral factors, prices, utilization, supply/borrow APR. Base is the only borrowable asset. Always uses th… (chainId, comet)

### continuum-dao

`defiModules`: `protocols/evm/continuum-dao`

- `buildEvmMultisignBodyContinuumDaoAttachVeCtmFromMcp` — Build MultiSignAgentWallet.attachVeCtm(nodeKey, tokenId, nodeInfo, groupId). groupId is the attaching KeyGen's mpc-auth GroupId (server-filled; do not pick ano… (chainId, tokenId, mpaWallet)
- `buildEvmMultisignBodyContinuumDaoCancel` — Build ContinuumDAO.cancel(proposalId). Proposer while Pending, or the proposal guardian. Builds the unsigned batch, signs the management envelope, and POSTs /m… (chainId, proposalId)
- `buildEvmMultisignBodyContinuumDaoCastVoteBravoFromMcp` — Build ContinuumDAO.castVote. support: 0 against, 1 for, 2 abstain. proposalId may be a catalog id (including 0) or the governor hash. Refuses unless the propos… (chainId, proposalId, support)
- `buildEvmMultisignBodyContinuumDaoCastVoteDelta` — Build ContinuumDAO.castVoteWithReasonAndParams. weights must be nOptions + 1 (final slot is NOTA). Same Active / snapshot / hasVoted gates as Bravo. Builds the… (chainId, proposalId, weights)
- `buildEvmMultisignBodyContinuumDaoCreateLock` — Build batch: CTM approve (if needed) + VotingEscrow.create_lock. Amount must be >= on-chain minimumLock (default 1 CTM). Duration 1–208 weeks. Linea only. Do n… (chainId, amountHuman, lockDurationSeconds)
- `buildEvmMultisignBodyContinuumDaoDelegate` — Build VotingEscrow.delegate(delegatee). Moves all veCTM voting power from the KeyGen to delegatee. Refuses the zero address and this KeyGen (use undelegate). G… (chainId, delegatee)
- `buildEvmMultisignBodyContinuumDaoExecute` — Build ContinuumDAO.execute(proposalId). proposalId may be a catalog id (including 0) or the governor hash. Call after Succeeded. Queue is not implemented. Buil… (chainId, proposalId)
- `buildEvmMultisignBodyContinuumDaoForumSignIn` — Build an EIP-712 forum login multi-sign (no EVM tx). Refuses when this node already has a live forum session for the KeyGen (getForumSession plus forum_me logg… (chainId)
- `buildEvmMultisignBodyContinuumDaoIncreaseAmount` — Build batch: CTM approve (if needed) + increase_amount. Refuses expired locks, zero amount, and amounts above KeyGen CTM balance. Builds the unsigned batch, si… (chainId, tokenId, amountHuman)
- `buildEvmMultisignBodyContinuumDaoIncreaseUnlockTime` — Build increase_unlock_time on Linea VotingEscrow. lockDurationSeconds is from the week boundary to the new unlock (1–208 weeks) and must land after the current… (chainId, tokenId, lockDurationSeconds)
- `buildEvmMultisignBodyContinuumDaoLiquidate` — Build VotingEscrow.liquidate. Refuses if attached, liquidations disabled, locked amount <= 100 gwei, or penalty would be zero. Expired locks withdraw instead o… (chainId, tokenId)
- `buildEvmMultisignBodyContinuumDaoMerge` — Build VotingEscrow.merge. Both NFTs must be owned by the KeyGen and unattached. Blocked if either token is node-attached. Builds the unsigned batch, signs the… (chainId, fromTokenId, toTokenId)
- `buildEvmMultisignBodyContinuumDaoProposeBravo` — Build ContinuumDAO.propose for a Bravo (For/Against/Abstain) proposal and POST /proposals/create (pendingOnChain) before the multi-sign request is submitted. R… (chainId, title, description, type, forumKey)
- `buildEvmMultisignBodyContinuumDaoProposeDeltaFromMcp` — Build ContinuumDAO.propose for a Delta multi-option proposal and POST /proposals/create (pendingOnChain) before the multi-sign request is submitted. Requires d… (chainId, title, description, type, options, nWinners, forumKey)
- `buildEvmMultisignBodyContinuumDaoRequestDetach` — Build NodeProperties.setNodeRemovalStatus(tokenId, true). Compose from the KeyGen that owns the attached NFT (not the current withdraw authority unless they ar… (chainId, tokenId, nodeProperties)
- `buildEvmMultisignBodyContinuumDaoSplit` — Build VotingEscrow.split. New lock and remainder must each keep at least minimumLock (default 1 CTM). Blocked while node-attached or expired. Builds the unsign… (chainId, tokenId, extractedHuman)
- `buildEvmMultisignBodyContinuumDaoTransfer` — Build VotingEscrow.transferFrom. Refuses node-attached tokens, the zero address, and self-transfers. Builds the unsigned batch, signs the management envelope,… (chainId, tokenId, to)
- `buildEvmMultisignBodyContinuumDaoUndelegate` — Return veCTM voting power to the KeyGen. There is no undelegate() on VotingEscrow — this calls delegate(self). Refuses if power is already at this KeyGen. Buil… (chainId)
- `buildEvmMultisignBodyContinuumDaoWithdraw` — Build VotingEscrow.withdraw for an expired, unattached lock. Refuses if still locked or node-attached. Builds the unsigned batch, signs the management envelope… (chainId, tokenId)
- `continuumDaoComposeProposalAction` — Compose a ContinuumDAO proposal action or preview a full draft. Load MCP servers etherscan (official V2, get_contract_abi with chainid 59144/59141) and foundry… (chainId)
- `continuumDaoExplainProposal` — Deconstruct a ContinuumDAO proposal for the operator. Walks every user action (Bravo) or every option (Delta), labels encoder no-ops as signaling, flags C3 / v…
- `continuumDaoFetchDelegates` — Read VotingEscrow.delegates(account). self is true when voting power is not delegated away. Linea only. (chainId, rpcUrl, account)
- `continuumDaoFetchLiveProposals` — Answer “what proposals are live now?”. Lists the backend catalog (including negative ids on the superseded Linea governor) and overlays ContinuumDAO.state usin…
- `continuumDaoFetchProposal` — Fetch one proposal from the public ContinuumDAO backend (GET /proposals/:id). Id may be negative: -2 and -1 are the two proposals from the superseded Linea gov… (id)
- `continuumDaoFetchProposals` — List proposals from the public ContinuumDAO backend (POST /proposals). start/end are catalog id indexes (end exclusive), not offsets, and may be negative: the…
- `continuumDaoFetchProposalState` — Read ContinuumDAO.state and proposalVotes. `proposalId` may be a backend catalog id (0, -1, -2, …) — those resolve to the row’s onchainId hash and governorAddr… (chainId, rpcUrl, proposalId)
- `continuumDaoFetchProposalVotes` — Who voted on a ContinuumDAO proposal and how. Reads Governor VoteCast / VoteCastWithParams for live or past proposals. Each voter includes attached (NodeProper… (chainId, rpcUrl, proposalId)
- `continuumDaoFetchVotingPower` — Read ContinuumDAO getVotes(account) and live proposalThreshold() (max of 1000e18 ve power and 1% of total votes). Gate propose on votes >= threshold. Linea onl… (chainId, rpcUrl, account)
- `continuumDaoForumCreateIdea` — Post an Idea or Suggestion (discussion only) to Ideas & Suggestions for ContinuumDAO protocol / DAO management. Pass address so the server loads the node forum… (title, content)
- `continuumDaoForumCreateTopic` — Create a formal proposal thread in a Governance section: decision, election, treasury, constitution, or admin. Requires getVotes >= live proposalThreshold(). P… (title, content)
- `continuumDaoForumDelete` — Admin or moderator soft-delete on forum.continuumdao.org. Pass address so the server loads the node forum session and continues only if forum_me loggedIn is tr…
- `continuumDaoForumFetchPost` — Read one forum post by pid. Not the whole thread. (pid)
- `continuumDaoForumFetchThread` — Fetch a forum thread from forum.continuumdao.org. Returns cid and section (ideas / decision / election / treasury / constitution / admin). index 0 is the origi…
- `continuumDaoForumMarkRead` — Mark Forum topic(s) read for the logged-in user (clears NodeBB Unread and topic notifications). Pass address so the server loads the node forum session and con…
- `continuumDaoForumMarkUnread` — Mark one Forum topic unread for the logged-in user. Pass address so the server loads the node forum session and continues only if forum_me loggedIn is true. Re…
- `continuumDaoForumMe` — Current forum user, votes, canPropose (Governance), canPostIdea (Ideas), and canPostMpa (MPA Wallet Chat listings / mailbox). canPropose is governor getVotes(a…
- `continuumDaoForumReact` — Toggle an allowlisted reaction on a post: +1, -1, heart, tada, eyes. Pass address so the server loads the node forum session and posts only if forum_me loggedI… (pid, emoji)
- `continuumDaoForumRecent` — List the most recent posts across the whole forum that the caller may read. Requires hours (last X hours) or since (ISO date / unix timestamp). Newest first. R…
- `continuumDaoForumReply` — Post an English reply (max 8000 characters) to a forum thread (Ideas, Governance, or MPA listing). Pass address so the server loads the node forum session and… (content)
- `continuumDaoForumReplyCount` — Reply count for a forum thread (excludes the original post).
- `continuumDaoForumResolve` — Parse a ContinuumDAO forumKey URL into a NodeBB topic id.
- `continuumDaoForumSearch` — Search forum.continuumdao.org. Case-insensitive match on a new thread title or any post body. Optional hours (last X hours) or since (ISO date / unix timestamp…
- `continuumDaoForumSections` — Forum category ids: ideas (DAO discussion), Governance (decision/election/treasury/constitution/admin), and MPA Wallet Chat (offer/request/directory/opportunit…
- `continuumDaoForumSignInEligible` — Check whether an address may EIP-712 sign in to the forum. Call get_forum_session and forum_me first. Call this only when there is no live node session (logged… (address)
- `continuumDaoForumSignOut` — Revoke the forum ticket and destroy NodeBB sessions for that user. Pass address or ticket. This tool then deletes that ticket from the node (POST /clearForumSe…
- `continuumDaoForumUnread` — List unread Forum topics for the logged-in user (NodeBB Unread). Pass address so the server loads the node forum session and continues only if forum_me loggedI…
- `continuumDaoForumUserPostIds` — List forum post ids for a username (no bodies). Then call forum_fetch_post for each pid. (username)
- `continuumDaoMpaFlag` — Flag an MPA listing for moderators. Pass address so the server loads the node forum session and continues only if forum_me loggedIn is true. Requires reason an… (reason)
- `continuumDaoMpaListing` — Post one MPA Wallet Chat listing (offer, request, directory, or opportunity). Pass address so the server loads the node forum session and posts only if forum_m… (kind, summary, details, capabilities)
- `continuumDaoMpaMailboxList` — List Agent Mail threads for this KeyGen (KeyGens group). Agents never use NodeBB chat — mailbox only.
- `continuumDaoMpaMailboxOpen` — Open or fetch the Agent Mail thread with another KeyGen username. Optional first content. KeyGens only; not NodeBB chat. (username)
- `continuumDaoMpaMailboxSend` — Send an Agent Mail message to another KeyGen (username or existing tid/url). Pass address so the server loads the node forum session and sends only if forum_me… (content)
- `continuumDaoMpaRetract` — Retract your MPA listing (locks immediately; soft-delete 90 days later). Pass address so the server loads the node forum session and continues only if forum_me…
- `continuumDaoRegisterProposal` — Retry the catalog write when propose did not leave a row. POST /proposals/create, and on 409 POST /proposals/repair to update title, description, forumKey, typ… (onchainId, title, description, proposer, forumKey, type, configuration)
- `continuumDaoSimulateProposal` — Dry-run a Bravo or Delta ContinuumDAO proposal without creating a sign request. Load MCP servers etherscan (official V2) and foundry first. Returns foundry.fil… (chainId, configuration)
- `continuumDaoTechnocoreBind` — Bind a Technocore did:key to this forum user. Signature is Ed25519 over username|nodeKey|did|host. Durable identity; Technocore room posts stay ephemeral. Neve… (did, signature)

### continuum-dao-marketplace

`defiModules`: `protocols/evm/continuum-dao`

- `buildEvmMultisignBodyContinuumDaoMarketplaceAuctionBid` — Bid on a live auction. Refuses when this KeyGen is the seller or already owns the veCTM. Builds the unsigned batch, signs the management envelope, and POSTs /m… (chainId, tokenId, seller, priceWei)
- `buildEvmMultisignBodyContinuumDaoMarketplaceCancelAuction` — Cancel a pending auction that has no bids. The veCTM returns to the seller. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignReque… (chainId, tokenId)
- `buildEvmMultisignBodyContinuumDaoMarketplaceCreateAuction` — Start an auction and escrow the veCTM. Refuses an attached KeyGen. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Retur… (chainId, tokenId, paymentToken, deadline, reserveWei, minIncrementWei)
- `buildEvmMultisignBodyContinuumDaoMarketplaceCreateListing` — List a veCTM. Approves the marketplace for the token id when needed. Refuses an attached KeyGen. Linea only. Builds the unsigned batch, signs the management en… (chainId, tokenId, paymentToken, askWei, deadline)
- `buildEvmMultisignBodyContinuumDaoMarketplaceCreateOffering` — Offer on a veCTM this KeyGen does not own. Refuses an attached KeyGen. WETH sends msg.value and still approves WETH for later fulfillment. Builds the unsigned… (chainId, tokenId, paymentToken, bidWei, deadline)
- `buildEvmMultisignBodyContinuumDaoMarketplaceDelist` — Delist this KeyGen’s open veCTM listing. Use this when the KeyGen is the seller. Do not buy that listing. Builds the unsigned batch, signs the management envel… (chainId, tokenId)
- `buildEvmMultisignBodyContinuumDaoMarketplaceFulfillListing` — Buy a listed veCTM. Refuses when this KeyGen already owns it or is the seller, and tells you to delist instead. WETH sends msg.value. Builds the unsigned batch… (chainId, tokenId, seller, paymentToken, priceWei)
- `buildEvmMultisignBodyContinuumDaoMarketplaceFulfillOffering` — Accept an offering on a veCTM this KeyGen owns. Refuses an attached KeyGen. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignReque… (chainId, tokenId, buyer, paymentToken, priceWei)
- `buildEvmMultisignBodyContinuumDaoMarketplaceRescind` — Rescind this KeyGen’s open offering. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success —… (chainId, tokenId)
- `buildEvmMultisignBodyContinuumDaoMarketplaceSettleAuction` — Settle a completed or expired auction. A completed auction transfers the veCTM to the highest bidder. Builds the unsigned batch, signs the management envelope,… (chainId, tokenId, seller)
- `fetchContinuumDaoMarketplaceActivity` — One address’s marketplace orders and auctions, including past sales and bids. (address)
- `fetchContinuumDaoMarketplaceAuctions` — Live veCTM auctions. derivedStatus is Active while the auction is open, including before any bid meets the reserve. storedStatus stays Pending until a qualifyi…
- `fetchContinuumDaoMarketplaceConfig` — Marketplace config: payment tokens, WETH, duration bounds, fee tiers. Falls back to the Linea contract when the API is down.
- `fetchContinuumDaoMarketplaceFeePreview` — Protocol fee for a veCTM price. Uses the API, then on-chain fee tiers. (tokenId, price)
- `fetchContinuumDaoMarketplaceListings` — Unfiltered page of open veCTM listings, created order, up to 100, with nextCursor. includeInactive adds past sales. Pass viewer as the KeyGen. viewerAction "de…
- `fetchContinuumDaoMarketplaceOfferings` — Open veCTM offerings. includeInactive adds fulfilled and rescinded rows. API first, then marketplace logs.
- `fetchContinuumDaoMarketplaceToken` — One veCTM: live listing, offerings, and auction, plus history of closed sales and auctions with bids. (tokenId)
- `quoteContinuumDaoMarketplaceFeeAlternative` — Alternative to paying a KeyGen month in the fee token or CTM. Returns the live monthly fee, 12 times that fee, the veCTM threshold, and one direct listing whos… (rpcUrl)
- `searchContinuumDaoMarketplace` — Rank veCTMs for sale. Returns a short list already sorted by price per locked CTM, price, locked CTM, unlock, or deadline. Filters: min/max locked CTM, unlock…

### curve-dao

`defiModules`: `protocols/evm/curve-dao`

- `buildEvmMultisignBodyCurveAddLiquidity` — Create mpc-auth multiSignRequest for Curve add_liquidity (optional gauge.deposit when stakeInGauge). Pool must be from fetch_important_pools. Builds the unsign… (chainId, pool, amountsHuman, slippagePercent)
- `buildEvmMultisignBodyCurveDaoBatch` — Create and submit mpc-auth multiSignRequest for a Curve Router NG swap via @curvefi/api populateSwap. Optionally batches ERC-20 approve txs when allowance is i… (chainId, tokenIn, tokenOut, amountHuman, slippagePercent)
- `buildEvmMultisignBodyCurveGaugeDeposit` — Stake or unstake Curve LP in the gauge (required for advertised gauge_crv_apy). Set withdraw:true to unstake. Builds the unsigned batch, signs the management e… (chainId, pool, lpAmountHuman)
- `buildEvmMultisignBodyCurveRemoveLiquidity` — Create mpc-auth multiSignRequest for Curve remove_liquidity. Unstake from the gauge first if LP is staked. Builds the unsigned batch, signs the management enve… (chainId, pool, lpAmountHuman, slippagePercent)
- `curveDaoFetchImportantPools` — Official api.curve.fi catalog of ~100 important pools (TVL-ranked, dead/zero-TVL dropped). The only Curve list tool — do not dump factories or call fetchAllCur… (chainId)
- `curveDaoFetchLpYields` — LP yields for the same ~100 important Curve pools (baseApy + gauge_crv_apy + TVL). gauge_crv_apy requires staking LP in the gauge. (chainId)
- `curveDaoQuote` — Fetch a Curve Router NG quote via @curvefi/api getBestRouteAndOutput. Returns output amount, route, and optional priceImpactPercent. Does NOT create a sign req… (chainId, tokenIn, tokenOut, amountHuman)
- `curveDaoQuoteAddLiquidity` — Quote Curve add_liquidity for an important pool. Copy pool + amountsHuman onto the build tool. (chainId, pool, amountsHuman)
- `curveDaoQuoteRemoveLiquidity` — Quote balanced Curve remove_liquidity for an important pool. (chainId, pool, lpAmountHuman)

### derive

`defiModules`: `protocols/evm/derive`

- `buildDeriveCancelMultisign` — Cancel a Derive open order (v3 private/cancel via EIP-191 login delivery). Requires subaccountId from ctm_derive_fetch_subaccounts. Does not move the current-c… (chainId, instrumentName, orderId, subaccountId)
- `buildDeriveDepositAddressTransferMultisign` — Ethereum L1 ERC-20 transfer to a registered Derive deposit address (standard / keeper sweep). Call ctm_derive_register_deposit_address first. useCustomGas. Bui… (chainId, underlyingErc20, amountHuman, depositAddress)
- `buildDeriveDepositNewSubaccountMultisign` — Ethereum L1 only (chainId 1 / 11155111): approve the underlying ERC-20 to ACTION_MANAGER, then depositToNewSubaccount. First credit creates the trading + fallb… (chainId, protocolAsset, underlyingErc20, amountHuman, managerId)
- `buildDeriveHypeVaultDepositMultisign` — HyperEVM (999) HYPE vault: wrap native HYPE to WHYPE if needed, approve, deposit. First credit creates a Standard Margin subaccount. useCustomGas. Builds the u… (chainId, amountHuman)
- `buildDerivePlaceOrderMultisign` — EIP-712 Derive options order (delivery derive_exchange). Requires subaccountId from ctm_derive_fetch_subaccounts. Does not move the current-chain token unless… (chainId, instrumentName, direction, amount, limitPrice, maxFee, subaccountId)
- `buildDeriveReplaceOrderMultisign` — EIP-712 replace of a Derive open order. Requires subaccountId from ctm_derive_fetch_subaccounts and exactly one of orderIdToCancel or nonceToCancel. EIP-712 or… (chainId, instrumentName, direction, amount, limitPrice, maxFee, subaccountId)
- `buildDeriveSocketDepositMultisign` — Socket FAST deposit of USDC/WETH/WBTC on Ethereum, Optimism, Base, or Arbitrum. Native 0x0 wraps to WETH. Pays a small native bridge fee. useCustomGas. Builds… (chainId, token, amountHuman)
- `buildDeriveTransferSpotMultisign` — EIP-712 transfer_spot. Use toSubaccountId 0 + newSubaccountManager to create an extra subaccount after the first funded one. First account is a deposit (L1 / S… (chainId, fromSubaccountId, toSubaccountId, newSubaccountManager, asset, amount)
- `deriveFetchCurrenciesSummary` — List Derive currencies from public/get_all_currencies. Used to map asset-row symbols (ETH, USDC, BTC, …). load_defi_protocol derive activates defi:derive:marke…
- `deriveFetchMarketSnapshotSummary` — Live Derive ticker: mark, index, bid/ask, greeks. Throws if no live price. (instrumentName)
- `deriveFetchOhlcvSummary` — OHLCV for a Derive option (instrumentName) or underlying index (currency + marketKind index). Default is ~96 bars for the interval (not a 14-day dump). Envelop…
- `deriveFetchOpenOrdersSummary` — Open Derive orders for a subaccountId. Follow with cancel/replace. (subaccountId)
- `deriveFetchOptionChainAgentSummary` — Compact Derive expiry ladder for a currency (counts + min/max strike per YYYYMMDD). Does not dump every instrument. Then ctm_derive_fetch_tickers for that expi… (currency)
- `deriveFetchPendingDepositsSummary` — Poll public/get_pending_deposits for the KeyGen wallet. credited:false means wait; then call fetch_subaccounts. First deposit is L1, Socket (ETH/OP/Base/Arb),…
- `deriveFetchPortfolioSummary` — Derive private/get_subaccount portfolio for a funded subaccountId. (subaccountId)
- `deriveFetchPositionsSummary` — Open Derive option positions for a subaccountId from fetch_subaccounts. (subaccountId)
- `deriveFetchRiskUniversesSummary` — List Derive risk universes (manager_id + collaterals). Required before the first deposit. Pick a manager that lists ETH options and USDC (or the row currency).
- `deriveFetchSubaccountsSummary` — List Derive subaccount ids for the KeyGen executor. Empty list returns funded:false and notes to deposit from a fundable logo row (L1 / Socket / HYPE vault). T…
- `deriveFetchTickersSummary` — ATM strike/premium ladder for one Derive expiry (bid/ask/mark). expiryDate is YYYYMMDD — string or number. Default ~9 strikes around index; pass ladder:"all" f… (currency, expiryDate)
- `deriveOrderQuoteSummary` — Dry-run Derive fill / margin preview (public/order_quote). (instrumentName, direction, amount, limitPrice)
- `deriveRegisterDepositAddress` — public/register_deposit_address — deterministic Ethereum L1 deposit address for this wallet. Then transfer the token with ctm_derive_build_deposit_address_tran… (wallet)
- `deriveSearchInstrumentsSummary` — Search Derive option instrument names by strike, expiry, or C/P suffix. (currency, query)

### ethena

`defiModules`: `protocols/evm/ethena`

- `buildEvmMultisignBodyEthenaSusdeCooldownShares` — Build sUSDe cooldownShares batch step. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success… (chainId, susdeSharesHuman)
- `buildEvmMultisignBodyEthenaSusdeRedeemToUsde` — Build sUSDe redeem when cooldown is off. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on succes… (chainId, susdeSharesHuman)
- `buildEvmMultisignBodyEthenaUnstakeClaim` — Build unstake claim after cooldown. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success — d… (chainId)
- `buildEvmMultisignBodyEthenaUsdeStakeToSusde` — Build batch: USDe approve + sUSDe deposit. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on succ… (chainId, usdeAmountHuman)
- `ethenaFetchSusdeApySummary` — sUSDe staking APY plus USDe-per-share from the vault. Use this (not web search) for USDe yield. Ethereum mainnet. rpcUrl is injected.

### euler-v2

`defiModules`: `protocols/evm/euler-v2`

- `buildEvmMultisignBodyEulerV2BorrowCollateralDepositBatch` — Build Euler v2 borrow collateral deposit batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on… (chainId, vault, collateralAsset, amountHuman)
- `buildEvmMultisignBodyEulerV2BorrowCollateralWithdrawBatch` — Build Euler v2 borrow collateral withdraw batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } o… (chainId, vault, collateralAsset, amountHuman)
- `buildEvmMultisignBodyEulerV2BorrowRepayBatch` — Build Euler v2 borrow repay batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success — do… (chainId, vault, amountHuman)
- `buildEvmMultisignBodyEulerV2IsolatedBorrowBatch` — Build Euler v2 isolated borrow loop batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on succ… (chainId, vault, collateralAsset, borrowAsset, collateralAmountHuman, loopBorrowWeis)
- `buildEvmMultisignBodyEulerV2IsolatedLendDepositBatch` — Build Euler v2 vault deposit/lend batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on succes… (chainId, vault, assetAmountHuman)
- `buildEvmMultisignBodyEulerV2MerklDistributorClaim` — Build wallet-wide Merkl Distributor.claim. Pass keyGenId + chainId; server fetches proofs. Optional claimData override. rEUL is omitted (Euler unlock stays in… (chainId)
- `buildEvmMultisignBodyEulerV2VaultWithdraw` — Build Euler v2 vault withdraw/redeem batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on suc… (chainId, vault, sharesHuman)
- `eulerV2FetchEarnVaultsSummary` — Euler Earn vaults (curated, not isolated lend) for an underlying with live supply APY. Use this (not web search) for Euler earn rates. Copy evaultAddress for d… (chainId, underlyingAddress)
- `eulerV2FetchLendVaultsSummary` — Euler v2 isolated lend vaults for an underlying asset. Returns evaultAddress for build_isolated_lend_multisign. (chainId, underlyingAddress)
- `eulerV2FetchMerklRewardsSummary` — Wallet-wide Merkl claimables for this address on a chain (not Euler-only). Pass keyGenId or user. Other venues’ campaigns can appear. rEUL is omitted (skippedR… (chainId)

### gmx

`defiModules`: `protocols/evm/gmx`

- `buildEvmMultisignBodyGmxCancelBatch` — Create and submit mpc-auth multiSignRequest to cancel a pending GMX order (classic on-chain). Builds the unsigned batch, signs the management envelope, and POS… (chainId, orderId)
- `buildEvmMultisignBodyGmxDecreaseBatch` — Create and submit mpc-auth multiSignRequest for GMX classic decrease order (close/reduce perp). Builds the unsigned batch, signs the management envelope, and P… (chainId, symbol, direction, orderType, sizeUsdHuman, collateralToken)
- `buildEvmMultisignBodyGmxGmDepositBatch` — Create and submit mpc-auth multiSignRequest for GMX v2.2c GM pool deposit (approve SyntheticsRouter, ExchangeRouter multicall). Keeper executes asynchronously.… (chainId, marketSymbol, collateralToken, collateralAmountHuman)
- `buildEvmMultisignBodyGmxGmWithdrawBatch` — Create and submit mpc-auth multiSignRequest for GMX v2.2c GM pool withdrawal (approve SyntheticsRouter, ExchangeRouter multicall). Keeper executes asynchronous… (chainId, marketSymbol, gmAmountHuman)
- `buildEvmMultisignBodyGmxIncreaseBatch` — Create and submit mpc-auth multiSignRequest for GMX classic increase order (open/add perp). Optional takeProfitPriceUsdHuman / stopLossPriceUsdHuman attach nat… (chainId, symbol, direction, orderType, sizeUsdHuman, collateralToken, collateralAmountHuman)
- `buildEvmMultisignBodyGmxStakeGmxBatch` — Create and submit mpc-auth multiSignRequest to stake GMX via RewardRouter. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignReques… (chainId, amountHuman)
- `buildEvmMultisignBodyGmxUnstakeGmxBatch` — Create and submit mpc-auth multiSignRequest to unstake GMX via RewardRouter. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequ… (chainId, amountHuman)
- `gmxFetchGmApy` — Fetch estimated GM liquidity pool APY for each GMX market (sorted highest first). Read-only. (chainId)
- `gmxFetchGmMarkets` — List GMX GM liquidity pool markets with long/short collateral symbols and estimated APY. Read-only. (chainId)
- `gmxFetchMarketPrices` — Latest GMX index mark, collateral USD, and official funding (fundingFactorPerSecond, longsPayShorts, hourly/APR labels). Borrow-per-second is a cost caveat, no… (chainId, symbol, collateralSymbol)
- `gmxFetchMarketsSummary` — List GMX V2 perp markets for a chain (symbol, market token, maxLeverageLabel). Read-only; uses GMX HTTP API. (chainId)
- `gmxFetchOhlcv` — OHLCV candle table for a GMX perp index (USD). Default timeframe 15m. Read-only via GMX HTTP API. (chainId, symbol)
- `gmxFetchOrdersSummary` — Fetch pending GMX orders (orderId) for build_cancel_multisign. Read-only. (chainId, executorAddress)
- `gmxFetchPositionsForExecutor` — Fetch open GMX perp positions (symbol, direction, sizeUsd, collateralSymbol) for build_decrease. Read-only. (chainId, executorAddress)
- `gmxFetchStakingPower` — Fetch GMX token staking power for an executor address. Read-only. (chainId, executorAddress)

### hyperliquid

`defiModules`: `protocols/evm/hyperliquid`

- `buildEvmMultisignBodyHyperliquidBridgeDepositBatch` — Create and submit mpc-auth multiSignRequest to deposit USDC from Arbitrum to Hyperliquid via Bridge2 (ERC20 transfer). chainId must be Arbitrum One (42161) or… (chainId, usdHuman)
- `buildEvmMultisignBodyHyperliquidCancelBatch` — Create and submit mpc-auth multiSignRequest to cancel a Hyperliquid open order. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignR… (chainId, coin, oid)
- `buildEvmMultisignBodyHyperliquidCloseBatch` — Create and submit mpc-auth multiSignRequest to close/reduce a perp (IoC reduce-only limit via CoreWriter). Builds the unsigned batch, signs the management enve… (chainId, coin, limitPxHuman, szHuman)
- `buildEvmMultisignBodyHyperliquidDelegateOnlyBatch` — Create and submit mpc-auth multiSignRequest to delegate staked HYPE to a validator. Builds the unsigned batch, signs the management envelope, and POSTs /multiS… (chainId, hypeHuman, validator)
- `buildEvmMultisignBodyHyperliquidLimitOrderBatch` — Create and submit mpc-auth multiSignRequest for a Hyperliquid limit/IoC order. Plain limit: CoreWriter (useCustomGas). When takeProfitTriggerPxHuman, stopLossT… (chainId, coin, limitPxHuman, szHuman)
- `buildEvmMultisignBodyHyperliquidStakeDepositBatch` — Create and submit mpc-auth multiSignRequest to stake HYPE via CoreWriter. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest… (chainId, hypeHuman)
- `buildEvmMultisignBodyHyperliquidStakeWithdrawBatch` — Create and submit mpc-auth multiSignRequest to unstake HYPE via CoreWriter. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignReque… (chainId, hypeHuman)
- `buildEvmMultisignBodyHyperliquidUndelegateBatch` — Create and submit mpc-auth multiSignRequest to undelegate HYPE from a validator. Builds the unsigned batch, signs the management envelope, and POSTs /multiSign… (chainId, hypeHuman, validator)
- `buildEvmMultisignBodyHyperliquidUsdClassTransferBatch` — Create and submit mpc-auth multiSignRequest to move USDC between spot and perp margin. Builds the unsigned batch, signs the management envelope, and POSTs /mul… (chainId, usdHuman)
- `buildEvmMultisignBodyHyperliquidVaultDepositBatch` — Create and submit mpc-auth multiSignRequest for Hyperliquid vault deposit. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignReques… (chainId, vaultAddress, usdHuman)
- `buildEvmMultisignBodyHyperliquidVaultWithdrawBatch` — Create and submit mpc-auth multiSignRequest for Hyperliquid vault withdraw (includes accrued PnL). Builds the unsigned batch, signs the management envelope, an… (chainId, vaultAddress, usdHuman)
- `buildHyperliquidBorrowLendMultisign` — Supply, withdraw, borrow, or repay on Hyperliquid Core lend via L1 /exchange EIP-712 — not CoreWriter. No useCustomGas. trigger_sign_result without txParams; b… (chainId, coin, operation)
- `buildHyperliquidBridgeWithdrawMultisign` — Create and submit mpc-auth multiSignRequest to withdraw USDC from Hyperliquid to Arbitrum via withdraw3 (EIP-712, delivered to /exchange). chainId 999 or 998.… (chainId, usdHuman)
- `buildHyperliquidTrailingStopMultisign` — Create and submit mpc-auth multiSignRequest for a Hyperliquid perp trailing stop (EIP-712 L1 trailingStop action to /exchange — no useCustomGas). Retracement i… (chainId, coin, szHuman, trailingOffsetHuman)
- `buildHyperliquidUpdateLeverageMultisign` — Set per-market leverage (cross or isolated) on Hyperliquid via L1 /exchange EIP-712 signing — not CoreWriter. No useCustomGas. trigger_sign_result without txPa… (chainId, coin, leverage)
- `hyperliquidFetchDelegationsForExecutor` — HYPE delegations by validator for executor. (executorAddress)
- `hyperliquidFetchLendMarketsSummary` — Hyperliquid Core lend reserves with current supply APR and borrow APR (yearly rates, not APY), utilization, LTV, and totals. Collateral (HYPE, UBTC) earns no s…
- `hyperliquidFetchLendPositionsSummary` — User Hyperliquid Core lend positions (supplied/borrowed), health, and whether manual borrow is enabled. Portfolio-margin accounts disable the manual borrow act… (executorAddress)
- `hyperliquidFetchMarketSnapshotSummary` — Live mark/mid price, official hourly funding, plus recent OHLCV candles for a Hyperliquid perp. Uses metaAndAssetCtxs for live prices and funding (not stale ca… (coin)
- `hyperliquidFetchMarketsSummary` — List native Hyperliquid crypto perp markets. HIP-3 stocks (xyz:AAPL) are ctm_hyperliquid_fetch_stock_markets. Pass dex to list one builder. chainId 999 mainnet…
- `hyperliquidFetchOhlcvSummary` — OHLCV candle history for a Hyperliquid perp over an explicit lookback or time range. Set lookbackDays to match the operator request exactly (e.g. "last 7 days"… (coin)
- `hyperliquidFetchOpenContextSummary` — Per-market trading context: account value, withdrawable, margin used, leverage setting, mark price, available buy/sell size. Resolves ticker/name (AAPL, Apple)… (executorAddress, coin)
- `hyperliquidFetchOpenOrdersSummary` — Pending Hyperliquid open orders for executor (oid, coin, side, price, size). (executorAddress)
- `hyperliquidFetchPositionsForExecutor` — Open Hyperliquid perp positions for executor (size, entry, uPnL, liq price, leverage, margin). (executorAddress)
- `hyperliquidFetchStakingSummaryForExecutor` — HYPE staking summary: delegated and undelegated amounts. (executorAddress)
- `hyperliquidFetchStockMarketsSummary` — HIP-3 / equity stock perps (xyz:AAPL, TSLA, …) with dex, displayName, and category. Trading only — not a savings APR. Native crypto: ctm_hyperliquid_fetch_mark…
- `hyperliquidFetchUsdClassBalancesSummary` — Spot USDC available and perp withdrawable USD for spot↔perp transfers. (executorAddress)
- `hyperliquidFetchUserVaultEquitiesSummary` — USD equity the user holds in Hyperliquid vaults. (executorAddress)
- `hyperliquidFetchVaultApysSummary` — Hyperliquid vault APRs sorted descending (HLP first). Use this for idle USDC yield compare — not HIP-3 stocks. Same catalog cap as fetch_vaults.
- `hyperliquidFetchVaultCatalogSummary` — Vault catalog by TVL with APR (mainnet only; may take ~10–15s). Pass executorAddress to merge user-held vaults.
- `hyperliquidSearchMarketsSummary` — Search Hyperliquid perp markets across all dexes by ticker (AAPL, BTC), display name, or keyword (Apple, tesla). Case-insensitive. Returns canonical coin names… (query)

### hyperliquidOutcome

`defiModules`: `protocols/evm/hyperliquidOutcome`

- `buildEvmMultisignBodyHyperliquidOutcomeCancel` — Cancel a resting Hyperliquid outcome order by oid. EIP-712, no gas. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Retu… (chainId, outcome, side, oid)
- `buildEvmMultisignBodyHyperliquidOutcomeMerge` — Merge Yes and No shares back into quote (userOutcome mergeOutcome). Omit amount or set amountMax to merge the maximum. EIP-712, no gas. Builds the unsigned bat… (chainId, outcome)
- `buildEvmMultisignBodyHyperliquidOutcomeMergeQuestion` — Merge Yes shares across one question into quote tokens. EIP-712, no gas. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest.… (chainId, question)
- `buildEvmMultisignBodyHyperliquidOutcomeNegate` — Convert No shares of one outcome into Yes shares of the other outcomes in the question. EIP-712, no gas. Builds the unsigned batch, signs the management envelo… (chainId, question, outcome, amountHuman)
- `buildEvmMultisignBodyHyperliquidOutcomeOrder` — Limit buy or sell a Hyperliquid HIP-4 outcome side. Asset id is 100000000 + 10*outcome + side (yes=0, no=1). EIP-712 Agent signature, no gas. IOC crosses the b… (chainId, outcome, side, isBuy, limitPxHuman, szHuman)
- `buildEvmMultisignBodyHyperliquidOutcomeSplit` — Split quote tokens into equal Yes and No shares (userOutcome splitOutcome). EIP-712, no gas. Builds the unsigned batch, signs the management envelope, and POST… (chainId, outcome, amountHuman)
- `hyperliquidOutcomeFetchMarketsSummary` — Live Hyperliquid HIP-4 outcome markets from outcomeMeta, with Yes/No mids. Optional query substring. Chain 999.
- `hyperliquidOutcomeFetchMarketSummary` — One Hyperliquid outcome market plus both Yes and No order books. (outcome)
- `hyperliquidOutcomeFetchOpenOrdersSummary` — Open Hyperliquid outcome orders (#encoding coins) for a user. (user)
- `hyperliquidOutcomeFetchOrderbookSummary` — l2Book for one Hyperliquid outcome side (default yes). (outcome)
- `hyperliquidOutcomeFetchPositionsSummary` — Quote balances and HIP-4 share balances (+encoding) for a HyperCore address. Not ERC20s — do not add_to_token_registry. (user)

### lido

`defiModules`: `protocols/evm/lido`

- `buildEvmMultisignBodyLidoClaimWithdrawal` — Build tx for Lido claimWithdrawal. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success — do… (chainId)
- `buildEvmMultisignBodyLidoRequestWithdrawals` — Build batch for Lido withdrawal queue (approve + requestWithdrawals). Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Re… (chainId, stEthAmountsWei)
- `buildEvmMultisignBodyLidoSubmit` — Create and submit mpc-auth multiSignRequest for Lido ETH stake (submit). Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest.… (chainId, valueWei)
- `buildEvmMultisignBodyLidoUnwrapWstEth` — Build tx for wstETH unwrap. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success — do not ca… (chainId, wstEthAmountWei)
- `buildEvmMultisignBodyLidoWrapStEth` — Build batch for wstETH wrap. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success — do not c… (chainId, stEthAmountWei)
- `lidoFetchStethAprSummary` — Recent stETH staking APR from the official Lido API. Use this (not web search) when comparing ETH staking vs lending. Ethereum mainnet.

### maple-syrup

`defiModules`: `protocols/evm/maple`

- `buildEvmMultisignBodyMaplePoolRequestRedeem` — Build Maple PoolV2 requestRedeem batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success… (chainId, pool, sharesHuman, receiver)
- `buildEvmMultisignBodyMapleSyrupDeposit` — Build Maple Syrup router deposit batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success… (chainId, syrupRouter, pool, asset, amountHuman)
- `mapleSyrupFetchMarketsSummary` — List Maple Syrup pools on a chain with live weekly/monthly APY and TVL. Use this (not web search) for Maple lending rates. Copy pool + syrupRouter + asset for… (chainId)
- `mapleSyrupFetchMarketSummary` — One Maple Syrup pool (by pool address or underlying) with weekly/monthly APY and TVL. Copy pool + syrupRouter + asset for deposit/redeem. Do not web-search Map… (chainId)

### morpho

`defiModules`: `protocols/evm/morpho`

- `buildEvmMultisignBodyMorphoBlueBorrowBatch` — Build Morpho Blue borrow batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success — do no… (chainId, marketId, loanToken, amountHuman)
- `buildEvmMultisignBodyMorphoBlueRepayBatch` — Build Morpho Blue repay batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success — do not… (chainId, marketId, loanToken, amountHuman)
- `buildEvmMultisignBodyMorphoBlueSupplyBatch` — Build Morpho Blue supply batch (lend loan token, e.g. USDC, into a market). Builds the unsigned batch, signs the management envelope, and POSTs /multiSignReque… (chainId, marketId, loanToken, amountHuman)
- `buildEvmMultisignBodyMorphoBlueSupplyCollateralBatch` — Build Morpho Blue supplyCollateral batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on succe… (chainId, marketId, collateralToken, amountHuman)
- `buildEvmMultisignBodyMorphoBlueWithdrawBatch` — Build Morpho Blue withdraw batch (withdraw supplied loan token). Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns… (chainId, marketId, loanToken, amountHuman)
- `buildEvmMultisignBodyMorphoBlueWithdrawCollateralBatch` — Build Morpho Blue withdrawCollateral batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on suc… (chainId, marketId, amountHuman)
- `buildEvmMultisignBodyMorphoMerklDistributorClaim` — Build wallet-wide Merkl Distributor.claim. Pass keyGenId + chainId; server fetches proofs. Optional claimData override. Builds the unsigned batch, signs the ma… (chainId)
- `buildEvmMultisignBodyMorphoMidnightBorrowBatch` — Build Morpho Midnight fixed-rate borrow batch (approve collateral + authorize + supply collateral and take bids). Builds the unsigned batch, signs the manageme… (chainId, marketId, borrowAmountHuman, collateralAmountHuman, collateralToken)
- `buildEvmMultisignBodyMorphoMidnightCancelLendOfferBatch` — Cancel a Morpho Midnight lend offer (exhaust the offer group) and withdraw unused Blue-parked funds. Builds the unsigned batch, signs the management envelope,… (chainId, group)
- `buildEvmMultisignBodyMorphoMidnightLendBatch` — Build Morpho Midnight fixed-rate lend batch (approve + authorize bundles + take asks via MidnightBundles). Builds the unsigned batch, signs the management enve… (chainId, marketId, amountHuman)
- `buildEvmMultisignBodyMorphoMidnightLendOfferBatch` — Build a Morpho Midnight lend limit offer. Parks the loan token in Morpho Blue (variable yield) until a borrower takes the offer via BlueBuyCallback. Builds the… (chainId, marketId, amountHuman)
- `buildEvmMultisignBodyMorphoMidnightRepayBatch` — Build Morpho Midnight repay + withdraw collateral batch (full exit at/after maturity). Builds the unsigned batch, signs the management envelope, and POSTs /mul… (chainId, marketId)
- `buildEvmMultisignBodyMorphoVaultDepositBatch` — Build Morpho vault deposit batch (wrap/approve + deposit). Works with listed V1 and V2 vaults. On chain 4663, robinhoodEarn: true pre-fills Robinhood Earn (Ste… (chainId, vaultAddress, underlyingAddress, amountHuman)
- `buildEvmMultisignBodyMorphoVaultWithdraw` — Build Morpho vault withdraw batch. Works with listed V1 and V2 vaults. On chain 4663, robinhoodEarn: true pre-fills Robinhood Earn (Steakhouse USDG). Builds th… (chainId, vaultAddress, amountHuman)
- `morphoFetchBlueMarketsSummary` — Morpho Blue variable-rate markets. Filter by collateral/loan ticker or address (AAPLc, USDC). query "stock" lists Coinbase B20 collateral books. Returns market… (chainId)
- `morphoFetchEarnVaultsSummary` — Morpho-listed earn vaults (V1 + V2 unified). Filter by deposit asset symbol/address and/or case-insensitive vault name search. On chain 4663, query "robinhood… (chainId)
- `morphoFetchMerklRewardsSummary` — Wallet-wide Merkl claimables for this address on a chain (not Morpho-only). Pass keyGenId or user. Other venues’ campaigns can appear. rEUL is omitted. Follow… (chainId)
- `morphoFetchMidnightBooksSummary` — Morpho Midnight fixed-rate books (order books). Filter by loan/collateral; returns marketId, maturity, and implied lend/borrow APR for Midnight multisign tools. (chainId)
- `morphoFetchMidnightMakerOffersSummary` — Open Morpho Midnight maker lend offers for a user. Use group/callback/callbackData to cancel and withdraw unused Blue park. (user)
- `morphoFetchMidnightPositionsSummary` — Morpho Midnight positions for a user (lend/borrow). Use marketId for repay. (user)
- `morphoFetchMidnightQuoteSummary` — Quote a Morpho Midnight book fill. side asks = lend, bids = borrow. assets is raw loan-token units. (marketId, side, assets)
- `morphoFetchPositionsSummary` — Morpho vault and Blue positions (collateral, borrow, and loan-token supply) for a user. Midnight positions stay on ctm_morpho_fetch_midnight_positions. (user, chainId)
- `morphoFetchStockMarketsSummary` — Coinbase B20 stock-backed Morpho markets on Base (default 8453). Variable Blue + fixed Midnight. Tickers OK (AAPLc). Not idle stable yield — isolated equity co…

### pendle

`defiModules`: `protocols/evm/pendle`

- `buildEvmMultisignBodyPendleAddLiquidityBatch` — Pendle V2: add LP multiSign. 30-min expiry default. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId… (chainId, tokensIn, market, slippagePercent)
- `buildEvmMultisignBodyPendleMintPyBatch` — Pendle V2: mint PT+YT multiSign (approve + Convert). 30-min expiry default. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignReque… (chainId, tokenIn, pt, yt, amountHuman, slippagePercent)
- `buildEvmMultisignBodyPendleMintSyBatch` — Pendle V2: mint SY multiSign. 30-min expiry default. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId… (chainId, tokenIn, sy, amountHuman, slippagePercent)
- `buildEvmMultisignBodyPendleRedeemPyBatch` — Pendle V2: redeem PT+YT multiSign. After expiry, pass amountYtHuman 0 (PT only). 30-min expiry default. Builds the unsigned batch, signs the management envelop… (chainId, pt, yt, tokenOut, amountPtHuman, slippagePercent)
- `buildEvmMultisignBodyPendleRedeemRewardsBatch` — Pendle V2: redeem on-chain interest and incentives from SY, YT, and LP (usually PENDLE) via Hosted SDK. Not merkle airdrops. 30-min expiry default. Builds the… (chainId)
- `buildEvmMultisignBodyPendleRedeemSyBatch` — Pendle V2: redeem SY multiSign. 30-min expiry default. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { request… (chainId, sy, tokenOut, amountHuman, slippagePercent)
- `buildEvmMultisignBodyPendleRemoveLiquidityBatch` — Pendle V2: remove LP multiSign. 30-min expiry default. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { request… (chainId, market, lpAmountHuman, tokensOut, slippagePercent)
- `buildEvmMultisignBodyPendleSwapBatch` — Pendle V2: approve Convert tx.to then swap token ↔ PT/YT. 30-min multiSign expiry unless expiryDate is set. Fresh Convert at build time. Builds the unsigned ba… (chainId, tokenIn, tokenOut, amountHuman, slippagePercent)
- `pendleFetchMarketsSummary` — Pendle V2: live (unexpired) markets on chainId, scanned from Core, TVL-ranked, hard cap 100. Matured YT markets are omitted. Includes points[] campaigns. Use c… (chainId)
- `pendleFetchMerkleRewards` — Pendle V2: list off-chain airdrop rows for a wallet (token, amount). Informational only — Core has no claim proofs. Tell the user to claim airdrops on app.pend… (user)
- `pendleFetchPositions` — Pendle V2: this wallet’s LP holdings from official Core dashboard (including matured). Not the node token list. Use before remove LP. ~4 CU. Do not treat claim… (user)
- `pendleFetchPricesSummary` — Pendle V2: USD prices for listed or searched asset ids (GET /v1/prices/assets). Do not use Convert as a ticker. (chainId)
- `pendleQuoteAddLiquidity` — Pendle V2 Convert quote: add LP. keepYt+yt = zero-price-impact (keep YT in the wallet instead of selling it into the AMM). (chainId, tokensIn, market, slippagePercent)
- `pendleQuoteMintPy` — Pendle V2 Convert quote: mint PT+YT from an underlying or SY. (chainId, tokenIn, pt, yt, amountHuman, slippagePercent)
- `pendleQuoteMintSy` — Pendle V2 Convert quote: wrap underlying into SY. (chainId, tokenIn, sy, amountHuman, slippagePercent)
- `pendleQuoteRedeemPy` — Pendle V2 Convert quote: redeem PT+YT to underlying or SY. After expiry, pass amountYtHuman 0 (PT only). (chainId, pt, yt, tokenOut, amountPtHuman, slippagePercent)
- `pendleQuoteRedeemSy` — Pendle V2 Convert quote: unwrap SY to underlying. (chainId, sy, tokenOut, amountHuman, slippagePercent)
- `pendleQuoteRemoveLiquidity` — Pendle V2 Convert quote: remove LP to tokensOut (use underlying). After expiry still works. Copy market + lpAmountHuman from ctm_pendle_fetch_positions. (chainId, market, lpAmountHuman, tokensOut, slippagePercent)
- `pendleQuoteSwap` — Pendle V2 Hosted SDK Convert quote: token ↔ PT or YT (this is also how you trade points). Fresh calldata; do not cache as a price ticker. (chainId, tokenIn, tokenOut, amountHuman, slippagePercent)
- `pendleSearchAssets` — Pendle V2: search live markets by ticker, 0x, or chainId-0x. Prefers unexpired hits; returns a matured market only if nothing live matched or you looked up tha… (chainId, query)

### prediction-markets

`defiModules`: `protocols/evm/trueo`

- `getPredictionMarketSummary` — Full selected prediction market. venue defaults to trueo (market address). For Hyperliquid pass venue hyperliquid and venueMarketId = outcome id. Does not requ… (venueMarketId)
- `listMyPredictionMarketsSummary` — Live Yes/No, trading window, and resolution for markets the user has bet on. Pass YES/NO tokenAddresses from get_token_registry and/or marketAddresses from pri…
- `searchPredictionMarketsSummary` — Venue-agnostic prediction market search (Trueo on Base and Hyperliquid outcome markets). Pass the operator topic verbatim as query. Omit venues to search both.…

### railgun

`defiModules`: `protocols/evm/railgun`

- `buildEvmMultisignBodyRailgunShield` — Shield an ERC-20 into a Railgun 0zk address. Call ctm_railgun_fee_quote first and tell the user the Railgun fee taken from the amount. purposeText is the Purpo… (chainId, tokenAddress, amountWei, railgunAddress)
- `buildEvmMultisignBodyWethUnwrap` — Withdraw this chain’s wrapped gas token back to native gas on the KeyGen. On Ethereum that is WETH back to ETH. This is a normal sign request, not a private Ra… (chainId, amountWei)
- `listRailgunBroadcasters` — List Railgun broadcasters for a private transfer or unshield. Call this on the originator immediately before broadcast_sign_result. ratio is the fee compared w… (chainId, tokenAddress, kind)
- `railgunFetchPopularAssets` — Top 5 public ERC-20s on a Railgun chain by recent shield count. This is the asset-row icon list, not the user shielded holdings. rpcUrl is injected. (chainId)
- `railgunFetchPrivateBalancesSummary` — Create the Railgun wallet on this KeyGen if it does not exist yet, and return its 0zk address. Omit keyGenId to use the node preferred KeyGen. Returns shieldSi…
- `railgunPrivateTransfer` — Propose a private Railgun transfer. This node signs it with its management key, then agrees its share. Call ctm_railgun_fee_quote first and tell the user the b… (chainId, tokenAddress, amountWei)
- `railgunUnshield` — Start an unshield to a public address. This node signs it with its management key, then agrees its share. Call ctm_railgun_fee_quote first and tell the user th… (chainId, tokenAddress, amountWei)

### sky

`defiModules`: `protocols/evm/sky`

- `buildSkyLockstakeCloseBatch` — Build Lockstake close position batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success —… (chainId, urnIndex)
- `buildSkyLockstakeDrawBatch` — Build Lockstake draw (borrow USDS). Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success — d… (chainId, usdsAmountHuman, urnIndex)
- `buildSkyLockstakeGetRewardBatch` — Build Lockstake getReward batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success — do n… (chainId, urnIndex)
- `buildSkyLockstakeStakePositionBatch` — Build Sky Lockstake open/stake batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success —… (chainId, skyAmountHuman)
- `buildSkyLockstakeWipeBatch` — Build Lockstake repay/wipe batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success — do… (chainId, usdsAmountHuman, urnIndex)
- `buildSkySusdsDepositFromUsdsBatch` — Build USDS → sUSDS ERC-4626 deposit batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on succ… (chainId, usdsAmountHuman)
- `buildSkySusdsRedeemToUsdsBatch` — Build sUSDS redeem to USDS batch. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on success — do… (chainId, sharesHuman)
- `skyFetchSusdsRateSummary` — Sky Savings Rate (sUSDS APY) from on-chain ssr(). Use this (not web search) for USDS savings. Ethereum mainnet. rpcUrl is injected.

### trueo

`defiModules`: `protocols/evm/trueo`

- `buildEvmMultisignBodyTrueoBurn` — Burn equal YES+NO back to TYD (or USDC via adapter). Not a bet. 30-minute expiry. Builds the unsigned batch, signs the management envelope, and POSTs /multiSig… (chainId, marketAddress, amountHuman)
- `buildEvmMultisignBodyTrueoCancelOrder` — Cancel an OrderManager order. Not a bet — allowed after close. 30-minute expiry. Builds the unsigned batch, signs the management envelope, and POSTs /multiSign… (chainId, marketAddress, side, orderId)
- `buildEvmMultisignBodyTrueoCreateOrder` — Create an OrderManager limit order (Yes or No). Refuses if the market closes within 5 minutes. 30-minute expiry. Builds the unsigned batch, signs the managemen… (chainId, marketAddress, side, amountHuman, tickLower, tickUpper)
- `buildEvmMultisignBodyTrueoMint` — Mint YES+NO from TYD (default) or USDC via TruthMarketAdapter. Base 8453. Not a bet — allowed near market close. 30-minute multiSign expiry. Builds the unsigne… (chainId, marketAddress, amountHuman)
- `buildEvmMultisignBodyTrueoRedeem` — Redeem winning outcome tokens after resolution. Not a bet. 30-minute expiry. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequ… (chainId, marketAddress, amountHuman)
- `buildEvmMultisignBodyTrueoSwap` — Buy Yes or No with TYD via UniversalRouterAdapter V4 swap. Refuses if the market closes within 5 minutes. extraJSON stores endOfTrading for Get Sig/Execute. 30… (chainId, marketAddress, side, amountHuman)
- `buildEvmMultisignBodyTrueoUnwrapTyd` — Redeem TYD shares back to Base USDC via the Yearn ERC-4626 vault. Not a market bet. No marketAddress. 30-minute expiry. Builds the unsigned batch, signs the ma… (chainId, amountHuman)
- `buildEvmMultisignBodyTrueoWrapTyd` — Mint TYD by depositing Base USDC into the Yearn ERC-4626 vault. Not a market bet. No marketAddress. 30-minute expiry. Builds the unsigned batch, signs the mana… (chainId, amountHuman)
- `trueoFetchCategoriesSummary` — Trueo category chips (Politics, Crypto, Sports, …). Use as category on search.
- `trueoFetchChanceSeriesSummary` — Yes/No chance samples for a pool id from fetch_market. Not candlesticks. Default hourly (3600s) over 14 days. 1H/1D/1W/All coerce to hourly. (poolId)
- `trueoFetchMarketSummary` — Selected Trueo market: rules, source, Yes/No %, TVL, size, tokens, pools, endOfTrading. Copy address for build_*. Writes: ctm_trueo_build_mint_multisign, ctm_t… (marketAddress)
- `trueoFetchOrderbookSummary` — Yes/No depth: live tick, implied price, OrderManager pending rows when rpcUrl is set, recent trades. (marketAddress)
- `trueoFetchTrendingSummary` — Trueo trending on Base (max 10; API does not page). More markets: ctm_trueo_search_markets with offset=0. Default: live and recently finished (14 days).
- `trueoSearchMarketsSummary` — Trueo-only search (query + category), pages of 10. Same rows as search_prediction_markets. If hasMore, pass nextOffset and excludeAddresses of listed addresses…

### uniswap-v4

`defiModules`: `protocols/evm/uniswap-v4`

- `buildEvmMultisignBodyUniswapV4CollectFeesBatch` — Create and submit mpc-auth multiSignRequest to collect fees from a Uniswap V4 position. Builds the unsigned batch, signs the management envelope, and POSTs /mu… (chainId, lpResponse, nftTokenId)
- `buildEvmMultisignBodyUniswapV4DecreaseLiquidityBatch` — Create and submit mpc-auth multiSignRequest to decrease Uniswap V4 position liquidity. Builds the unsigned batch, signs the management envelope, and POSTs /mul… (chainId, lpResponse, nftTokenId)
- `buildEvmMultisignBodyUniswapV4IncreaseLiquidityBatch` — Create and submit mpc-auth multiSignRequest to increase Uniswap V4 position liquidity. Builds the unsigned batch, signs the management envelope, and POSTs /mul… (chainId, lpResponse, nftTokenId)
- `buildEvmMultisignBodyUniswapV4LimitOrderBatchFromMcp` — Create and submit mpc-auth multiSignRequest for a UniswapX limit order (EIP-712 Permit2 witness). After sign + execute, delivery POSTs to Trade API /v1/order.… (chainId, fullLimitQuote, uniswapApiKey)
- `buildEvmMultisignBodyUniswapV4MintLiquidityBatch` — Create and submit mpc-auth multiSignRequest for minting a Uniswap V4 LP position. Standard: ERC-20 approve + Position Manager. Permissioned (positionManagerKin… (chainId, lpResponse)
- `buildEvmMultisignBodyUniswapV4PermissionedAllowlistFinalize` — Create and submit mpc-auth multiSignRequest to broadcast issuer-prepared allowlist calldata (e.g. Superstate setUserPermissionForInstrument). Requires partner… (chainId, to, data)
- `buildEvmMultisignBodyUniswapV4SkipPermit2Batch` — Create and submit mpc-auth multiSignRequest for a Uniswap V4 swap. May batch 1–3 EVM txs: ERC-20 approve(s) + Universal Router swap (or 1 tx for native-in). Bu… (chainId, tokenIn, swap, createSwapResponse, fullQuoteSnapshot, swapDeadlineUnix)
- `uniswapCreateSwap` — Call Uniswap Trade API POST /v1/swap to build Universal Router calldata from a prior quote. Returns { swap: { to, data, value, gasLimit? }, requestId? }. Does… (uniswapApiKey, fullQuoteFromPermit)
- `uniswapFetchLimitOrdersMcp` — List open UniswapX limit orders for a swapper (GET /v2/limit-orders). Ethereum mainnet only. Optional UNISWAP_API_KEY.
- `uniswapLimitOrderQuote` — Fetch a UniswapX limit order quote (POST /v1/limit_order_quote). Ethereum mainnet (chainId 1) only. Returns quote + permitData for EIP-712 signing. Does NOT cr… (type, amount, limitPrice, tokenIn, tokenOut, chainId, orderDeadline, uniswapApiKey)
- `uniswapLpClaimFees` — Call Uniswap LP API POST /lp/claim to collect accrued fees from a V4 position. (uniswapApiKey, chainId, tokenId)
- `uniswapLpCreatePosition` — Call Uniswap LP API POST /lp/create for a new V4 position. Returns token amounts and `create` transaction calldata. Does NOT create a sign request — call ctm_u… (uniswapApiKey, chainId, independentToken)
- `uniswapLpDecreasePosition` — Call Uniswap LP API POST /lp/decrease. Returns `decrease` transaction calldata. (uniswapApiKey, chainId, token0Address, token1Address, nftTokenId, liquidityPercentageToDecrease)
- `uniswapLpIncreasePosition` — Call Uniswap LP API POST /lp/increase. Returns `increase` transaction calldata. (uniswapApiKey, chainId, token0Address, token1Address, nftTokenId, independentToken)
- `uniswapTradeQuote` — Fetch a Uniswap V4 Trade API quote (POST /v1/quote). Returns classic quote JSON including quote.input/output amounts and routing. Does NOT create a sign reques… (type, amount, tokenIn, tokenOut, chainId, uniswapApiKey)
- `uniswapV4CheckPermissionsMcp` — Check Uniswap Trade API POST /v1/permissions for up to two tokens. Returns isPermissioned, isAllowlisted, kycUrl, issuer, and whether UR 2.2.0 is required. Cal… (tokens, chainId, uniswapApiKey)
- `uniswapV4FetchOhlcv` — Pool OHLCV: The Graph subgraph on pinned chains (1h/1d native, aggregated multiples, swap bucketing for sub-hour). Robinhood Chain (4663) uses Bitquery Uniswap… (chainId)
- `uniswapV4KycApplyLinkMcp` — Build an issuer KYC apply URL with KeyGen wallet / chain / token query params (no sign request). Use when check_permissions returns isAllowlisted=false and kyc… (walletAddress, chainId, kycUrl)
- `uniswapV4ListLpPools` — List Uniswap V4 LP pools for a chain. Default: standard no-hook ETH/USDC presets. Set permissioned=true for Permissioned Position Manager catalog (adapter curr… (chainId)
- `uniswapV4ListPositionsRegistryMcpPlaceholder` — List Uniswap V4 position NFTs from the node token registry (ERC721 entries for the Position Manager on this chain). Does not scan blockchain logs. Pass keyGenI… (chainId)
- `uniswapV4RegisterPositionFromMintTxPlaceholder` — Parse a completed mint transaction receipt for the new position tokenId and add it to the node token registry (management-signed). (chainId, txHash)
- `uniswapV4RegisterPositionNftPlaceholder` — Add a Uniswap V4 position NFT to the node token registry (ERC721, management-signed). Call after mint execute when tokenId is known. (chainId, tokenId)

### venice

`defiModules`: `protocols/evm/venice`

- `buildEvmMultisignBodyVeniceBurnDiem` — Burn DIEM to unlock locked sVVV on Base. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on succes… (chainId, amountHuman)
- `buildEvmMultisignBodyVeniceCompleteUnstakeDiem` — Claim DIEM after staked-DIEM unstake cooldown on Base. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { request… (chainId)
- `buildEvmMultisignBodyVeniceCompleteUnstakeSvvv` — Claim VVV after sVVV unstake cooldown on Base. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on… (chainId)
- `buildEvmMultisignBodyVeniceInitiateUnstakeDiem` — Start DIEM unstake (1-day cooldown) on Base. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on su… (chainId, amountHuman)
- `buildEvmMultisignBodyVeniceInitiateUnstakeSvvv` — Start sVVV unstake (7-day cooldown) on Base. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } on su… (chainId, amountHuman)
- `buildEvmMultisignBodyVeniceMintDiem` — Lock sVVV and mint DIEM on Base (preview with ctm_venice_read_mint_diem_preview). Builds the unsigned batch, signs the management envelope, and POSTs /multiSig… (chainId, svvvLockAmountHuman)
- `buildEvmMultisignBodyVeniceStakeDiem` — Stake DIEM for Venice API credits ($1/day per DIEM) on Base. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { r… (chainId, amountHuman)
- `buildEvmMultisignBodyVeniceStakeVvv` — Build batch: VVV approve + stake → sVVV on Base. Builds the unsigned batch, signs the management envelope, and POSTs /multiSignRequest. Returns { requestId } o… (chainId, amountHuman)
- `veniceListModelsSummary` — Venice AI model catalog (GET /models). Optional type filter (text, image, video, all). Requires VENICE_API_KEY in node Variables (server injects — do not pass…
- `veniceReadMintDiemPreviewSummary` — Preview DIEM mint rate and expected DIEM output for locking sVVV on Base. (rpcUrl, svvvLockAmountHuman)
- `veniceReadStakingStateSummary` — Read VVV/sVVV/DIEM wallet balances, staked DIEM, cooldown fields, mint rate, and estimated API credit on Base. (rpcUrl, executorAddress)
