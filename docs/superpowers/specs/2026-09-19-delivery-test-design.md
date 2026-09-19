# Delivery test: email deliverability diagnostic and cPanel server audit

*2026-09-19 — design for the "Delivery test" tab: public deliverability checks for
any address, a read-only server audit for locally hosted ones, uploaded-message
and diagnostic-inbox analysis, and scheduled monitoring.*


## Problem

The Config/Rules/Logs tabs let an admin fix the scanning chain, but nothing answers the question customers actually ask: "why does mail from/to `user@example.com` not arrive?". The user wants a new left-rail tab **Delivery test** where an email address (plus optional sending IP, DKIM selector, an uploaded `.eml`/bounce, or a real test mail to a unique diagnostic inbox) produces a clear, actionable report: pass / warning / fail / unknown / not-applicable per check, separated into **sending**, **receiving** and (for locally hosted addresses) **server** issues, with evidence, timestamps, severity, plain-English explanations and prioritized fixes (suggested DNS records, exact WHM/cPanel locations, commands). Progressive results, expandable details, exportable reports, optional scheduled monitoring. Real checks only — lookup failures are reported as *unknown*, never as findings; inbound MX hosts are never assumed to be senders; an address alone never proves mailbox existence, authentication or inbox placement.

Decisions taken with the user: one spec, **four phases** delivered as separate commits (A public checks → B cPanel audit → C advanced inputs → D monitoring/export); WHM admin first, reduced end-user variant designed now and shipped later; **system tools, never crates** (`openssl s_client`, `dig`/`delv`/`unbound-host`, `curl`; a missing tool → *unknown* with the reason); diagnostic inbox = `dt-<token>@<server hostname>` via an Exim router into a daemon-owned maildir; monitoring history in MySQL via migration 0003, run by the existing `msfe-ng monitor` cron, alerts via existing Telegram.

Verified on ncc (cPanel 11.138, AlmaLinux 8, Exim 4.100, OpenSSL 1.1.1k): `dig`, `delv`, `unbound-host`, `openssl`, `curl`, `exigrep`, `exiqgrep`, `uapi`/`whmapi1 --output=json`, `doveadm`, `csf` all present; local validating unbound on loopback (Spamhaus answers); `exim -bt <addr>` prints `router = virtual_user, transport = dovecot_virtual_delivery`; `uapi --user=<u> Email list_pops` returns `suspended_incoming/suspended_login`; `whmapi1 cphulk_status`, `cpgreylist_status`, `emailtrack_search`, `get_domain_info` work; `/etc/exim.conf.local` is the cPanel-supported customization file with `@PREROUTERS@` / `@ROUTERSTART@` / `@TRANSPORTSTART@` sections spliced by `/scripts/buildeximconf` (which `mailflow.rs` already runs); `/etc/valiases/<domain>`, `/etc/mailips`, `/var/cpanel/mainip`, `/etc/trueuserdomains`, `/var/cpanel/users/<u>` (MAX_EMAIL_PER_HOUR=200, MAX_DEFER_FAIL_PERCENTAGE), `/var/cpanel/domain_keys/public/<domain>`, `/var/log/exim_rejectlog` + `exim_paniclog` exist; `/etc/mail_reverse_dns` and dovecot logs do not (→ unknown / maillog).

Hard constraints: zero external crates (`Cargo.toml:26`); daemon bodies are UTF-8 `String` ≤ 4 MiB and the WHM CGI relays text → uploads are base64 in JSON (≈2.9 MB file cap); every non-GET holds `WRITE_LOCK` (`crates/msfe-ngd/src/main.rs:30`) for the whole handler, GETs are concurrent; `service::run_with_timeout` (`service.rs:45`) for any subprocess on a request path; daemon runs as root, admin = peer uid 0, other uids only `/api/user/*` (`http::peer_scope`).

## Existing code reused

See the module table below; the DNS wire code, DNSBL cache pattern, subprocess deadline runner, curl wrappers, jobs runner, users/panel/mailflow helpers, log index, queue view, CSF, stats/db and the SPA helpers are all existing code.

## Architecture decisions

**Run model.** A diagnostic is an **in-process run**: `POST /api/delivery/run` validates, registers the run in a `static RUNS: Mutex<HashMap<id, RunState>>`, spawns one coordinator thread and returns `{run_id}` in milliseconds (so `WRITE_LOCK` is released at once); `GET /api/delivery/run?id=` is lock-free and returns the checks finished so far (progressive). Coordinator: worker pool ≤ 6 threads over a dependency-ordered task list, per-probe timeouts (DNS 4 s × 2 tries, SMTP connect 5 s + session 10 s, openssl/curl 10 s/8 s), run deadline 90 s after which pending tasks become `unknown("run time limit reached")` and `done=true`; late results dropped by generation check. One running run per address (409), `delivery_runs_per_min` rate limit (429), finished reports cached 10 min (served unless `force`), persisted as `/var/cache/msfe-ng/delivery/<id>.json` 0600, evicted from memory after 30 min, pruned after 24 h. Background **jobs** only for the outbound test mail (phase C: real message leaves, must wait for Exim retries, survives restarts, one-at-a-time).

**Result model** (`delivery.rs`, new — not `doctor::Check`):
```rust
pub enum Verdict { Pass, Warn, Fail, Unknown, NotApplicable }  // pass|warn|fail|unknown|na
pub enum Scope { Sending, Receiving, Server }
pub enum Severity { Critical, High, Medium, Low, Info }
pub enum Category { Dns, Spf, Dkim, Dmarc, MailServers, TransportSecurity, Reputation, Account, Routing, OutboundIdentity, Services, Limits, Logs, Abuse, Message, Bounce, Inbox }
pub struct Evidence { label, text }
pub struct Fix { summary, dns_record: Option<String>, location: Option<String>, command: Option<String>, url: Option<String> }
pub struct Check { id, target: Option<String>, scope, category, verdict, severity, title, explanation, evidence: Vec<Evidence>, fix: Option<Fix>, at: u64, duration_ms: u64 }
pub struct Inputs { address, domain, local_part, ip: Option<IpAddr>, selector: Option<String>, days: u32, audit: bool, force: bool, user_scope: Option<String> }
pub struct Report { id, inputs, started, finished: Option<u64>, done, planned: Vec<String>, checks: Vec<Check>, tool_notes: Vec<String>, cached: bool }
// to_json/from_json (conftest style), summary() per scope, sorted() fail→warn→unknown→pass→na
```
"Could not look up" always yields `Unknown` with the reason in `explanation`.

**SSRF / input guard** (`netguard.rs`): `valid_hostname` (LDH labels, ≥2 labels, TLD not numeric), `parse_address` (≤254, one `@`, local ≤64), `is_public(ip)` (rejects loopback, private, link-local, multicast, unspecified, CGNAT, doc ranges, v4-mapped inner check, fc00::/7, fe80::/10), `own_addresses()`, `outbound_allowed(ip, local_audit)`. Every outbound TCP/curl target is checked on the **resolved IP**; curl pinned with `--resolve host:port:ip --proto =https --max-redirs 0 --max-filesize 65536`.

## Modules (msfe-core) and public API

| Module | Role | Key signatures |
|---|---|---|
| `dns.rs` | hand-rolled client: EDNS0 (DO bit), name decompression with pointer-loop guard, TTLs, UDP + TCP-53 on TC, per-client cache, RD=1 to system resolver / RD=0 to authoritative, `MSFE_NG_RESOLVER` override | `RType{A,Ns,Cname,Soa,Ptr,Mx,Txt,Aaaa,Ds,Tlsa,Caa}`, `RData`, `Rr{name,rtype,ttl,data}`, `Response{rcode,aa,tc,ad,answers,authority,additional,server,elapsed_ms}`, `DnsError{Timeout,Io,Refused,ServFail,FormErr,Malformed}`, `build_query`, `parse_message`, `read_name`, `Client::{system, at, query, query_authoritative, mx, addrs, txt, ptr}`, `reverse_name(ip)` |
| `dnsx.rs` | RRset compare across NS; DNSSEC ladder | `compare_across_ns(client, ns_hosts, name, rtype) -> Consistency{per_ns, agree}`; `DnssecState{Secure,Insecure,Bogus,Unknown}`; `dnssec_state(client,name,rtype)` — AD flag on loopback unbound → `delv +vtrace` → `unbound-host -v -D` → `dig +dnssec` → Unknown; `parse_delv`, `parse_unbound_host` |
| `spf.rs` | parser, lookup-limited walker, evaluator | `parse(txt)->Result<SpfRecord,String>`, `walk(client,domain)->Walk{lookups,void_lookups,loops,missing_includes,records,all_qualifier,uses_ptr,uses_macros,ip_count}`, `evaluate(client,domain,ip)->(SpfResult,trace)`, `split_txt_strings` |
| `dkim.rs` | selector discovery, record parse, key strength | `COMMON_SELECTORS` (default, google, selector1/2, k1..k3, s1/s2, mail, dkim, smtp, mandrill, everlytickey1/2, mxvault, protonmail*, zoho, sendgrid, sig1, cm, mailjet, mailgun, krs, pm, hs1/2, fm1..3 …), `parse_record(selector,txt)->DkimKey{k,p,revoked,t_testing,t_strict,h,bits,problems}`, `rsa_modulus_bits(der)` (SPKI→BIT STRING→RSAPublicKey INTEGER; PKCS#1 fallback), `discover(client,domain,user_selector)` (≤ 40 queries, CNAME followed) |
| `dmarc.rs` + `psl.rs` | record parse, org-domain inheritance, external report auth | `parse`, `lookup(client,domain)->Lookup{at,inherited,records,record,org_uncertain}`, `external_report_authorized(client,domain,rua_domain)`; `psl::organizational_domain(host)->(String, uncertain)` with a bundled two-level-TLD table |
| `smtpprobe.rs` | SMTP session probe (banner→EHLO→QUIT, never MAIL/RCPT to third parties) | `probe(ip,port,host,helo,connect,session)->SmtpProbe{banner,ehlo_name,caps,starttls,size,auth,pipelining,eightbit,smtputf8,transcript,error}`, `read_reply` (multi-line), `submit_local(addr,from,to,headers,body)`, `outbound_25_reachable(host,ips,timeout)` |
| `tlsprobe.rs` | `openssl s_client -starttls smtp -showcerts [-dane_tlsa_domain/-dane_tlsa_rrdata]`, `openssl x509 -noout -subject -issuer -dates -ext subjectAltName` | `starttls(ip,port,servername,tlsa,timeout)->TlsProbe{protocol,cipher,verify_code,verify_text,chain_len,leaf:Cert{subject,issuer,not_before,not_after,not_after_epoch,sans,self_signed},dane,transcript}`, `parse_s_client`, `parse_x509`, `hostname_matches`, `parse_openssl_date`, `openssl_version` |
| `httpclient.rs` | curl GET | `get(url,timeout,follow_redirects,pin:Option<(host,port,ip)>)->Result<HttpResult{status,body,effective_url}>` |
| `mtasts.rs` | MTA-STS, TLS-RPT, DANE, BIMI | `parse_sts_txt`, `parse_policy->StsPolicy{mode,mx,max_age}`, `mx_matches`, `parse_tlsrpt`, `parse_bimi`, `tlsa_records(client,mx)` |
| `dnsbl.rs` | curated table + query + 600 s cache | `Dnsbl{zone,name,kind:Ip4|Ip6|Domain,polarity,codes:[(prefix,meaning,severity)],refusal_codes,removal_url,note}`; `LISTS`: Spamhaus ZEN + DBL, SpamCop, Barracuda, UCEPROTECT L1/L2/L3, PSBL, Mailspike, s5h, SURBL multi, URIBL multi, DNSWL (positive); SORBS omitted (defunct), Abusix noted as key-required; `ListVerdict{NotListed,Listed(..),Refused,NoAnswer,Error}`, `query_ip`, `query_domain`, `cached_or_query` |
| `netguard.rs` | see above | |
| `deliveryrun.rs` | registry, pool, scheduler, cache, rate limit, persistence | `Ctx{cfg,inputs,dns,deadline,cancel,helo}`, `Task{id,deps,run}`, `Results` (checks + shared facts: mx, mx_ips, ns, spf, dkim, dmarc, tlsa, dnssec), `plan(inputs)`, `run_blocking(cfg,inputs,on_check)->Report`, `start(cfg,inputs)->Result<id,StartError{Invalid,Busy,RateLimited}>`, `snapshot(id)`, `cancel(id)`, `cached_report`, `sweep`, `report_dir` (`MSFE_NG_DELIVERY_DIR`) |
| `deliveryhtml.rs` | standalone HTML export (inline CSS, no JS) | `render(&Report)->String` |
| `cpaudit.rs` (B) | server audit areas | `Account{user,home,suspended,domain_kind:Local|Remote|SecondaryMx|Unknown}`, `resolve_account(domain)`, `tasks(inputs)`, `audit_{account,routing,outbound_identity,services,limits_filtering,logs_queues,abuse}`; pure parsers `parse_valiases`, `parse_exim_bt->Vec<BtHop{address,router,transport,remote,error}>`, `parse_localopts`, `parse_mailips`, `parse_cpuser`, `parse_ss_listeners`, `parse_list_pops(json,addr)`, `mask_address` |
| `deliverylog.rs` (B) | bounded exim/rejectlog/paniclog/maillog(dovecot) correlation | `parse_mainlog_line->LogLine{ts,id,kind:Arrival|Delivered|Failed|Deferred|Completed|Frozen|Reject,addr,host,ip,auth,router,transport,response}`, `parse_rejectlog_line`, `parse_dovecot_line`, `scan(base,address,days,max_bytes,mask_other)->Scan{messages:Vec<MessageTrail>,rejects,bytes_scanned,truncated}`, `summarize`, `cpanel_trace(user,addr)` (`uapi Email trace_delivery` / `whmapi1 emailtrack_search`) |
| `emlcheck.rs` (C) | uploaded message / bounce analysis | `parse_headers`, `parse_authentication_results->AuthResults`, `parse_received->Received{from_ip,by,date_epoch}`, `parse_date` (RFC 5322 via `civil`), `parse_dkim_signature`, `extract_links`, `SHORTENERS`, `RISKY_EXT`, `analyse_message(raw,ctx)->Vec<Check>`, `parse_dsn->Dsn{recipients:[{final_recipient,action,status,diagnostic,remote_mta}],original_headers}`, `classify_rejection(diag,remote)->Option<Rejection{provider,code,meaning,fix,url}>` (Gmail 421-4.7.0/550-5.7.1/5.7.26/4.7.28, M365 S3140/S3150/5.7.606/5.7.511, Yahoo TSS04/TS03, iCloud CS01/HM08, Proofpoint, Mimecast, cPanel "exceeded the max emails per hour", "sender verify failed", DNSBL), `analyse_bounce` |
| `diaginbox.rs` (C) | tokens, maildir, Exim fragments, test-mail job | `router_fragment(hostname)`, `transport_fragment()`, `wire(dry)`/`unwire`/`installed`, `create(ttl)->Inbox{token,address,expires}`, `poll(token)->InboxState{waiting,expired,messages:Vec<Vec<Check>>}` (analyse then delete), `sweep`, `TESTMAIL_JOB="delivery-testmail"`, `start_testmail(cfg,from,to,tag)`, `testmail_last()` |
| `deliverymon.rs` (D) | monitors + runs in MySQL, due-runs, regressions | `Monitor{id,address,options,interval_mins,enabled,owner,last_run_at,last_summary}`, `list/add/remove/due`, `run_due(cfg,dry)->Vec<String>` (from `monitor::run`), `store_run`, `runs(cfg,monitor_id,limit)`, `regressions(prev,cur)`, `prune` |

Daemon: `crates/msfe-ngd/src/delivery_api.rs` routed like `conf_api` (`p.starts_with("/api/delivery/")`). CLI: `cmd_delivery` in `main.rs`.

## Check catalogue

Fix templates substitute `{domain} {mx} {ip} {selector} {org}`. Any lookup/tool failure → **unknown** with reason.

### Phase A — public (S = sending, R = receiving)

**DNS** — `dns.domain` (S+R: NXDOMAIN everywhere → fail critical) · `dns.ns` (≥2 resolving NS → pass; 1 → warn; none → fail) · `dns.soa` (present; implausible timers → warn low) · `dns.auth_consistency` (MX, SPF TXT, SOA serial identical on every NS via RD=0; disagree → fail high, NS unreachable → warn) · `dns.dnssec` (Secure → pass; unsigned → pass info; DS present but bogus/unvalidated → fail critical; no validating resolver/tools → unknown with fix `msfe-ng resolver install` / bind-utils) · `dns.mx` (present → pass; absent with A/AAAA → warn "RFC 5321 A-fallback to {a}"; null MX `0 .` → pass, receiving checks NA per RFC 7505) · `dns.mx.priorities` (duplicates/>10 → warn) · `dns.mx.target` per MX (hostname with A/AAAA → pass; CNAME → warn RFC 2181; IP literal/NXDOMAIN → fail) · `dns.mx.addr_public` (private → fail, not probed) · `dns.mx.ptr` per MX IP (FCrDNS → pass; missing/non-confirming → warn; generic PTR → warn low) · `dns.apex_cname` (fail) · `dns.ttl` (300 s..7 d → pass else warn low) · `dns.ipv6` (no AAAA → warn low, info).

**SPF (S)** — `spf.record` (exactly one `v=spf1`; 0 → fail high, ≥2 → fail critical; fix `{domain}. IN TXT "v=spf1 mx a:{mailhost} -all"`) · `spf.syntax` · `spf.lookups` (≤8 pass, 9–10 warn, >10 fail critical, fix lists includes to drop) · `spf.void` (≤1 pass, 2 warn, >2 fail) · `spf.includes` (missing target → fail PermError, loop → fail, depth ≤10) · `spf.all` (`-all`/`~all` pass, `?all` warn, `+all` fail critical, missing warn) · `spf.ptr` (warn, RFC 7208 §5.5) · `spf.macros` (info-warn) · `spf.length` (string >255 → fail; total >450 → warn; fix shows split strings) · `spf.ip_scope` (>65536 addrs → warn) · `spf.eval` when `ip` given (pass/softfail warn/fail high/neutral warn/permerror fail/temperror unknown; fix `ip4:{ip}`).

**DKIM (S)** — `dkim.discovery` (user selector, `default`, common list; none found → **unknown** "supply the selector from a sent message's `s=`") · per selector: `dkim.record` (parse; empty `p=` → fail revoked) · `dkim.key` (RSA ≥2048 pass, 1024–2047 warn, <1024 fail high; ed25519 pass info; unparsable unknown; fix "cPanel → Email Deliverability → Manage → Generate 2048") · `dkim.testing` (`t=y` → warn) · `dkim.hash` (sha1-only → fail RFC 8301) · `dkim.multi` (>1 TXT → fail).

**DMARC (S)** — `dmarc.record` (one at `_dmarc.{domain}` or inherited from `{org}`; none → fail high "Gmail/Yahoo bulk-sender requirement"; ≥2 → fail; fix `_dmarc.{domain}. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@{domain}"`) · `dmarc.inherited` (info; org guessed → note) · `dmarc.syntax` · `dmarc.policy` (reject pass; quarantine pass info; none warn) · `dmarc.pct` (<100 warn) · `dmarc.sp` (weaker than p → warn) · `dmarc.rua` (none → warn) · `dmarc.rua_external.{rua_domain}` (`{domain}._report._dmarc.{rua_domain}` TXT; missing → warn; fix record) · `dmarc.alignment_hint` (info).

**Mail servers (R, per MX × v4/v6)** — `mx.connect` (5 s; primary fail high, backup warn; host has no IPv6 → NA) · `mx.banner` (220; 4xx/5xx greeting fail; >5 s warn) · `mx.ehlo` (EHLO name = MX or PTR → pass; else warn low) · `mx.caps` (STARTTLS+SIZE+8BITMIME pass; AUTH PLAIN/LOGIN before TLS on 25 → warn) · `mx.starttls` (absent → fail high) · `tls.handshake` (1.2/1.3 pass; ≤1.1 fail) · `tls.cert.valid` (verify 0 pass; self-signed/unknown issuer warn; expired fail) · `tls.cert.name` (mismatch warn, fail under MTA-STS enforce) · `tls.cert.expiry` (≤14 d warn) · `tls.chain` (leaf only with 20/21 → warn "missing intermediate").

**Transport security** — `mtasts.txt` (absent warn low; fix record) · `mtasts.policy` (fetch pinned, no redirects; error → fail when TXT present) · `mtasts.mode` (enforce pass; testing/none warn) · `mtasts.mx_match` (mismatch → fail critical) · `mtasts.max_age` · `tlsrpt.record` (absent info; fix record) · `dane.tlsa.{mx}` (absent → NA) · `dane.dnssec.{mx}` (TLSA without DNSSEC → fail) · `dane.match.{mx}` (openssl DANE match; mismatch → fail critical; fix `3 1 1 <sha256 SPKI>`) · `bimi.record` (info/NA).

**Reputation** — `rbl.ip.{list}.{ip}` for each MX IP (scope R; listed → **warn** with the explicit note "an inbound server listed on {list} matters only if it also sends — not assumed") and for the supplied sending IP (scope S; Spamhaus SBL/XBL/CSS, SpamCop, Barracuda → fail high; PBL → fail "dynamic range, use a smarthost"; UCEPROTECT L1 warn, L2/L3 warn low network-wide; PSBL/Mailspike/s5h warn); refusal codes (`127.255.255.254/255`, DNSWL `127.0.0.255`, URIBL `127.0.0.1`) → unknown "list refuses this resolver — Private DNS resolver → Install"; timeout → unknown; each listing carries meaning + removal URL from the table · `rbl.domain.{list}` (DBL/SURBL/URIBL; listed → fail high) · `rbl.dnswl.{ip}` (listed → pass info; else NA) · `rbl.summary`.

**Meta** — `meta.mailbox` always unknown ("an address alone cannot prove the mailbox exists, authenticates or lands in the inbox — use the diagnostic inbox / test mail or the server audit") · `meta.provider` (MX suffix → Google/M365/Proofpoint/Mimecast/Zoho/iCloud/Yahoo/GoDaddy/self-hosted cPanel; drives provider-specific wording).

### Phase B — cPanel audit (scope Server; only when the domain is local)

`acct.owner` (`users::owner_of_domain`; not hosted → whole audit NA) · `acct.domain_kind` (localdomains/remotedomains/secondarymx vs public MX; local but MX elsewhere → fail "WHM → Email Routing"; remote but MX here → fail) · `acct.suspended` (`SUSPENDED=1`) · `acct.mailbox` (`uapi --user Email list_pops_with_disk`: missing → check aliases else fail; suspended_incoming/login → fail; quota ≥90 % warn, full fail) · `acct.default_address` (`*:` in valiases: `:fail:` pass, `:blackhole:` warn, forward warn) · `route.exim_bt` (`exim -bt`; unrouteable → fail; remote transport for local domain → fail; alias chain info) · `route.aliases` (forwarders external → warn "enable SRS in WHM → Exim Config"; loop → fail) · `route.filters` (discard-all → warn) · `route.autoresponder` (info) · `route.boxtrapper` (on → warn) · `route.mailscanner` (wired/enabled, per-domain policy — info) · `route.cpanel_sa` (`mailflow::cpanel_sa_state_at`; double scan → warn) · `route.greylist` (`whmapi1 cpgreylist_status` info) · `out.ip` (`/etc/mailips` per-domain else `/var/cpanel/mainip`; mismatch with supplied ip → warn) · `out.helo` (`/etc/mailhelo`; FCrDNS → pass else fail high) · `out.spf_includes_ip` (`spf::evaluate` → fail critical with fix record) · `out.dkim_cpanel` (`/var/cpanel/domain_keys/public/{domain}` == published `default._domainkey` `p=`; `acl_dkim_disable`; missing/mismatch/disabled → fail "cPanel → Email Deliverability → Repair") · `out.smarthost` (`smarthost_routelist`, `queue_only` → warn) · `out.port25` (`outbound_25_reachable` to one external MX, EHLO/QUIT only; blocked → fail critical) · `out.ip_reputation` (DNSBL rows with sending severity) · `svc.exim/dovecot/cphulkd/mailscanner` (`systemctl is-active`) · `svc.listeners` (`ss -ltnp`: 25 missing fail; 465/587/143/993/110/995 missing warn) · `svc.csf_ports` (`/etc/csf/csf.conf` TCP_IN/TCP_OUT incl. OUT 25) · `svc.exim_version` (info, `require_secure_auth`) · `svc.tls_local` (STARTTLS/cert on 127.0.0.1:25/465/587 with servername mail.{domain}; self-signed → warn "AutoSSL") · `limit.hourly` (`MAX_EMAIL_PER_HOUR` vs `count_auth_sends`; ≥80 % warn, reached fail) · `limit.defer_fail` · `limit.ratelimit_acl` (localopts: acl_ratelimit, acl_dictionary_attack, senderverify off → warn, acl_requirehelo, acl_spamcop_rbl, rbl_whitelist, spam_header, exiscanall — info) · `limit.eximrejects` · `limit.spamassassin` (per-account enable, auto-delete ≤5 → warn) · `log.arrivals` (`deliverylog::scan`, default 2 days ≤7, ≤32 MiB live + ≤2 rotated; `**` failures → fail with remote text classified; `==` deferrals → warn) · `log.rejects` (rejectlog) · `log.panic` (non-empty → fail) · `log.auth_sends` (24 h count, bursts → warn) · `log.dovecot` (maillog imap/pop logins, repeated auth failures → warn) · `log.mailscanner` (`stats::sender_activity`/`messages`; recent quarantine → warn with links) · `log.cpanel_trace` (cross-check; discrepancy → warn, notes MailScanner in path) · `queue.pending` (`list_queue`; deferred warn; frozen fail with `queue_msg_view(..,"log")` excerpt) · `abuse.csf` (`csf -g` for supplied/sending IP and recent login IPs) · `abuse.cphulk` (`whmapi1 read_cphulk_records`) · `abuse.outbound_bursts` · `abuse.compromise_hints` (many login IPs/countries in 24 h → warn).

Tenant isolation: only `{user}`'s files and `uapi --user={user}`; log lines filtered to the address; other local addresses on the same line masked (`mask_address`). Read-only: no `exim -M*`, no restarts, no uapi mutations.

### Phase C — message / bounce / diagnostic inbox

`eml.auth_results` (last-hop Authentication-Results: spf/dkim/dmarc/arc; authserv-id shown) · `eml.dkim_signature` (`d=` alignment with From, `s=` feeds live `dkim.*`, `h=` covers From/Subject/Date, `l=`, `a=rsa-sha1` → fail) · `eml.alignment` (From vs Return-Path/Sender) · `eml.received_chain` (per-hop delay >5 min warn, >1 h fail; first external hop IP → PTR + `rbl.ip` rows) · `eml.headers.required` (Message-ID, Date, From, MIME-Version; Date skew) · `eml.headers.8bit` · `eml.lines` (>998 chars fail, bare LF warn) · `eml.list` (bulk mail without `List-Unsubscribe` + `List-Unsubscribe-Post: List-Unsubscribe=One-Click` → fail; non-bulk NA) · `eml.links` (raw-IP fail, shorteners warn, anchor/href host mismatch warn, link domains on DBL/SURBL fail) · `eml.attachments` (exe/scr/js/vbs/bat/cmd/com/pif/hta/jar/msi/ps1/lnk/iso/img → fail; docm/xlsm/pptm → warn; double extension; >10 MiB warn) · `eml.body` (HTML without text alternative warn, image-only warn, forms/scripts fail) · `eml.from_display` · `eml.reply_to`.
`bounce.dsn` (multipart/report delivery-status per recipient) · `bounce.status` (5.x.x fail, 4.x.x warn, class table) · `bounce.provider` (`classify_rejection` table with meaning/fix/url) · `bounce.returned_headers` (runs the header subset) · `bounce.non_dsn` (heuristic excerpt).
`inbox.received` (arrival within TTL) + `eml.*` on the message + `inbox.exim_log` (`<=` line: H=, P=esmtps → TLS, A=), `inbox.spf_here`, `inbox.mailscanner` (X-MailScanner headers/score), `inbox.tls_in` (`X=` cipher).

### Phase D — monitoring

Monitor = `Inputs` + interval 60 min..24 h (default 6 h), ≤ `delivery_max_monitors` (20), `owner` column. `msfe-ng monitor` (cron */5) → `run_due`: sequential `run_blocking`, store `delivery_runs`, compare per check id with the previous run; `pass→fail`, `pass→warn`, `warn→fail`, `*→unknown` twice → Telegram via `cooled_down("alert_delivery_<id>")`; recovery notified once; DNSBL/TLS regressions confirmed by an immediate re-run of that task before alerting. Exports per run (JSON/HTML) + CSV history.

## API (`delivery_api.rs`)

| Route | Body/params | Response | Lock |
|---|---|---|---|
| `POST /api/delivery/run` | `{address, ip?, selector?, days?, audit?, force?}` | `201 {run_id}` / `200 {run_id, cached:true}` / 400 / `409 {run_id}` / `429 {retry_secs}` | brief |
| `GET /api/delivery/run?id=` | | Report JSON + `done, planned, elapsed_ms, summary{sending,receiving,server}` / 404 | none |
| `POST /api/delivery/run/cancel` `{id}` | | `{ok}` | brief |
| `GET /api/delivery/report?id=&format=json\|html` | | JSON or standalone HTML (`Response::html`) | none |
| `GET /api/delivery/recent` | | last 20 `{id,address,started,summary}` | none |
| `GET /api/delivery/local?domain=` | | `{hosted, user?}` (cheap; enables the audit checkbox) | none |
| `GET /api/delivery/tools` | | `{openssl:{present,version}, dig, delv, unbound_host, curl, exim, uapi, whmapi1, resolver:{validating,on_loopback}}` | none |
| `POST /api/delivery/eml` | `{b64, kind:"message"\|"bounce", address?}` (≤2.9 MB file) | `{run_id}`; file 0600 under `backup_dir/delivery/`, deleted when done / 24 h | brief |
| `POST /api/delivery/inbox` | `{}` | `{token, address, expires}` or `503 {error, fix}` when not installed | brief |
| `GET /api/delivery/inbox?token=` | | `{waiting, expired, messages:[{received_at, checks}]}` (analysed + deleted on first poll) | none |
| `DELETE /api/delivery/inbox?token=` | | `{ok}` | WRITE_LOCK |
| `POST /api/delivery/inbox/install` / `uninstall` `{dry_run?}` | | wire report (like engine wire) | WRITE_LOCK |
| `POST /api/delivery/testmail` | `{from (local, owned), to (public), confirm:true}` | `{ok, job:"delivery-testmail", tag}` / 409 | job |
| `GET /api/delivery/testmail/last` | | result JSON | none |
| `GET\|POST\|DELETE /api/delivery/monitors`, `POST …/monitors/run {id}`, `GET …/monitors/runs?id=&limit=`, `GET …/monitors/run?run=` | | | as usual |

End-user variant (designed, shipped later): same handlers under `/api/user/delivery/{run,report,eml,inbox,monitors}` with `Inputs.user_scope=Some(req.user)` — domain ∈ `users::user_domains`, audit forced to that account, no testmail, monitors filtered by owner, 2 runs/min, evidence masking on.

## UI (`web/whm/index.html`)

- Rail button after Queues: `data-tab="delivery"`, Heroicons `paper-airplane` outline, label text node "Delivery test"; `tabs={…, delivery:renderDelivery}`; `let dlvTimer=null` + `clearInterval(dlvTimer)` in the tab-switch handler.
- `renderDelivery()`: **Input card** (email input, Run/Cancel, `<details>` Advanced: sending IP, DKIM selector, log days 1–7, "Include server audit" (enabled via `/api/delivery/local`), file upload message/bounce radio via FileReader ≤2.9 MB) · **progress line** (chips incl. new `.chip.unknown/.chip.na`, thin progress bar checks/planned, elapsed, "cached N min ago") · **results**: sections Sending / Receiving / Server, category `<h3>` groups, rows `.dot <verdict>` | `.kb sev-*` | title + `target` mono | short explanation | chevron → detail row with explanation, labelled `pre.log` evidence, **Fix** block (summary, `dns_record` in `pre.mono` with Copy button `copyBtn(text)`, location, command, url); sorted fail→warn→unknown→pass→na, NA rows collapsed · **Export**: JSON / HTML download (hoist `b64ToBlob` into top-level `textBlob/downloadBlob`) · **Diagnostic inbox card** (C): generate address, copyable, countdown, "Waiting for your message…" polled every 3 s via `dlvTimer`, results rendered with the same rows · **Test mail card** (C): from/to, `modal()` confirm, `followJob('delivery-testmail')`, then `/api/delivery/testmail/last` · **Monitors panel** (D): table (address, interval, last run chips, Run now, History modal with run list → full report, Export CSV, Remove), "Add monitor" pre-filled from the current run.
- Shared `renderDeliveryReport(r,{into,shown})` appends only new checks (no flicker); polling 1.5 s until `done`; 404 → "run is gone (daemon restarted?)".
- Mobile: input row wraps, result rows become a 2-column grid, evidence `pre` scrolls, override the `.card table` nowrap rule for `.dlv-scope`.
- CSS additions in `web/src/app.css` then `npm run build`: `.chip.unknown/.na`, `.dot.unknown/.na`, `.kb.sev-*`, `.dlv-scope`, `.dlv-row`, `.dlv-fix`, `.copybtn`, `.progress`.

## CLI

```
msfe-ng delivery test <address> [--ip <ip>] [--selector <s>] [--audit] [--days <n>] [--json] [--force]
msfe-ng delivery eml <file.eml> [--bounce] [--address <a>] [--json]
msfe-ng delivery monitor <list | add <address> [--interval-mins n] [--audit] [--ip ..] [--selector ..] | remove <id|address> | run [--dry-run] [--id n]>
msfe-ng delivery inbox <install [--dry-run] | uninstall [--dry-run] | status | sweep>
msfe-ng delivery testmail --from <a> --to <b> --tag <t> [--json]      (used by the job)
```
`accepted_flags` entries per sub, `usage_of("delivery")`, `print_help` lines. `delivery test` streams `[FAIL] spf.all  …` lines via `on_check`, then a summary; exit 0 no fail / 1 fail / 2 usage / 3 invalid input. `msfe-ng monitor` gains `deliverymon::run_due`; `housekeeping` gains `deliveryrun::sweep`, `diaginbox::sweep`, `deliverymon::prune`.

## Installer / packaging

- Diagnostic inbox wiring (`diaginbox::wire`, opt-in): between markers in `/etc/exim.conf.local` insert `.include_if_exists /etc/msfe-ng/diag-router.conf` under `@PREROUTERS@` and `.include_if_exists /etc/msfe-ng/diag-transport.conf` under `@TRANSPORTSTART@`; write the fragments with `sync::atomic_write`; run buildeximconf + restartsrv_exim (`MSFE_NG_SKIP_EXIM_CMDS` honoured). Router: `driver = accept; domains = $primary_hostname; local_parts = ^dt-[a-z0-9]{16}$; condition = ${if exists{/var/spool/msfe-ng/diag/active/$local_part}}; transport = msfe_ng_diag_delivery; no_more`. Transport: `appendfile, maildir_format, directory = /var/spool/msfe-ng/diag/box/$local_part, create_directory, directory_mode 0700, mode 0600, user = mailnull, group = mail, quota = 10M`. Removing the fragment file is the instant kill switch. Verify on ncc before coding that `@PREROUTERS@` precedes cPanel's `virtual_aliases`/`localuser` routers in the built `exim.conf`.
- `install.sh`: `mkdir -p /var/spool/msfe-ng/diag/{active,box}` (active root 0755, box mailnull:mail 0750), `/var/cache/msfe-ng/delivery` 0700, `backup_dir/delivery` 0700; migration `db/migrations/0003_delivery_monitors.sql` picked up by the existing migration install. `uninstall.sh`: `msfe-ng delivery inbox uninstall` before removing binaries, then remove the dirs. Cron unchanged.
- Config keys (config.rs + `to_public_json`): `delivery_runs_per_min=6`, `delivery_cache_secs=600`, `delivery_log_days=2`, `delivery_max_monitors=20`, `delivery_helo=""` (hostname).
- Migration 0003: `delivery_monitors(id, address, owner, options TEXT, interval_mins, enabled, created_at, last_run_at, last_summary, UNIQUE(address,owner))`, `delivery_runs(id, monitor_id, started_at, duration_ms, n_pass, n_warn, n_fail, n_unknown, report MEDIUMTEXT, KEY(monitor_id, started_at))`.

## Step sequence (each: code + tests + `cargo test --workspace` + clippy + `npm run build` when UI + commit; feature commit per step, release on "go")

0. Design spec `docs/superpowers/specs/2026-09-19-delivery-test-design.md` (this plan's content in the repo's spec style), committed first.

**Phase A**
1. `delivery.rs`, `netguard.rs`, `dns.rs` (client + parser + fake UDP server tests), `deliveryrun.rs` with the DNS tasks + `meta.mailbox`; `delivery_api.rs` run/cancel/report(json)/local/tools; rail tab with input, progress, grouped rows, JSON download; config keys. *End to end works after this commit.*
2. `spf.rs`, `dkim.rs`, `dmarc.rs`, `psl.rs` + tasks + UI categories.
3. `smtpprobe.rs`, `tlsprobe.rs` (+ `service::run_with_stdin`), `mx.*`/`tls.*`, PTR/FCrDNS, `meta.provider`.
4. `httpclient.rs`, `mtasts.rs` (MTA-STS, TLS-RPT, DANE, BIMI), `dnsx.rs` (DNSSEC ladder, authoritative consistency).
5. `dnsbl.rs` + reputation tasks + `spf.eval`; tool hints in the UI.
6. `deliveryhtml.rs` + HTML export + recent; CLI `delivery test`; wiki page `docs/wiki/Delivery-test.md`, CLI.md, README, `_Sidebar.md`.

**Phase B**
7. `users::owner_of_domain`, `cpaudit.rs` account + routing (`acct.*`, `route.*`) with parsers/fixtures; `audit` flag through API/CLI/UI (Server section).
8. `cpaudit` outbound identity + services + limits (`out.*`, `svc.*`, `limit.*`).
9. `deliverylog.rs` + logs/queue/abuse (`log.*`, `queue.*`, `abuse.*`), masking, `cpanel_trace`.

**Phase C**
10. `emlcheck.rs` (message + bounce), `mime.rs` visibility, `POST /api/delivery/eml`, upload UI, storage/sweep, CLI `delivery eml`.
11. `diaginbox.rs` (fragments, wire/unwire, tokens, maildir, poll, sweep), installer/uninstaller, inbox API + UI card, CLI `delivery inbox`.
12. Outbound test mail: `smtpprobe::submit_local` (moved from the CLI), `delivery-testmail` job + whitelist entry, correlation via `deliverylog`, API + UI card with confirm, CLI `delivery testmail`.

**Phase D**
13. Migration 0003, `deliverymon.rs`, `db::quote`, `monitor::run` hook, Telegram regressions, `housekeeping` prune, CLI `delivery monitor`.
14. Monitors UI panel, history modal, CSV/JSON/HTML export; end-user variant notes in the wiki; doctor hint "diagnostic inbox not installed" (info).

## Tests

- Unit tests per module with inline fixtures: DNS packets (compression, pointer loop, TC→TCP, AD/AA, EDNS) + a fake UDP server (timeout/retry/cache); SPF edge cases + walk over the fake server (limit overflow, void, loops); DKIM record tags + embedded 1024/2048/4096 DER keys + ed25519; DMARC/PSL; SMTP multi-line replies + fake SMTP server (incl. silent server timeout); `parse_s_client` on captured OpenSSL 1.1.1k and 3.x outputs + `parse_x509` + wildcard matching; MTA-STS policy/TXT; DNSBL reversal/codes/refusals/cache; netguard address table; run scheduler (deps, ≤6 concurrency high-water mark, deadline → unknown + done, late results dropped, Busy, rate limit, cache/force); cpaudit parsers on captured `exim -bt`, valiases, localopts, mailips, cpuser, `ss`, uapi JSON; deliverylog line fixtures (`<=`, `=>`, `->`, `**`, `==`, `Completed`, `*** frozen`, rejectlog, dovecot) + tempdir scan with a `.gz` + byte cap + masking; emlcheck (Authentication-Results variants, Received delays, DKIM-Signature, links, attachments, 998 chars, DSN fixtures Gmail/Outlook/Yahoo/Exim → `classify_rejection`); diaginbox wire/unwire idempotent on a fixture `exim.conf.local` (`MSFE_NG_EXIM_CONF_LOCAL`, `MSFE_NG_SKIP_EXIM_CMDS`), poll deletes after analysis; deliverymon regressions/due; deliveryhtml escaping; daemon request validation (400/404/429); CLI integration (`--bogus` → 2, invalid address → 3 offline, `delivery eml <fixture>` JSON, monitor without DB → clean error).
- Dev daemon (fixture-driven: `MSFE_NG_RESOLVER`, `MSFE_NG_CPANEL_ROOT`, `MSFE_NG_USERDOMAINS_FILE`, `MSFE_NG_DELIVERY_DIR`, `MSFE_NG_SKIP_EXIM_CMDS`, root daemon on a scratch socket + python TCP bridge, headless Firefox via `mar.py`): `gmail.com` (pass/NA), a domain without SPF, an IDN, `localhost`/`10.0.0.1` inputs rejected, a 2.9 MB upload, cancel mid-run, two concurrent runs, cache/force, progressive rendering, phone width.
- ncc: `msfe-ng delivery test <hosted address> --audit` (exim -bt, uapi, logs, CSF, openssl 1.1.1k parsing, Spamhaus via unbound, DANE against `posteo.de`); `delivery inbox install --dry-run` then real, send from Gmail to the generated address and watch the poller; `delivery testmail` to an external inbox; add a monitor, force `msfe-ng monitor`, check the Telegram alert; `inbox uninstall` leaves Exim clean (`exim -bV`, `exim -bt dt-x@host` unrouteable).

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| OpenSSL 1.1.1 vs 3.x output formats | tolerant parsers, both formats in fixtures, `openssl_version` in `tool_notes`, unparsable → unknown with transcript |
| `dig`/`delv`/`unbound-host` absent | DNSSEC ladder → unknown with install hint; `/api/delivery/tools` shows it up front |
| Blocklists refusing the resolver | refusal codes → unknown + "Private DNS resolver → Install"; Spamhaus rows skipped when no local resolver; never pass on refusal |
| No IPv6 on the host | `mx.connect.v6` → NA; AAAA still validated |
| Slow/silent MXs, long runs | per-probe timeouts, pool of 6, 90 s deadline, partial report with unknowns; primary MX probed first |
| MX ≠ sender, provider policies (UCEPROTECT, PBL on MX IPs) | per-list, per-scope severities; explicit wording |
| Transient DNS → false fail | SERVFAIL/timeout never fail; monitors confirm regressions before alerting |
| cPanel API field differences | defensive `Json::get`, fixtures from cPanel 138, unknown on missing fields |
| Log volume | byte-capped scans, `truncated` flag, `logindex` gz cache |
| Privacy of uploaded mail / inbox | 0600, deleted after analysis / 24 h; evidence limited to headers + 2 KiB body; no bodies in reports |
| Tenant data in logs | address-filtered scans, `mask_address`, user variant masks more |
| Probing outward from a mail server | EHLO/QUIT only, one connection per MX/family/run, 10-min cache, rate limit, HELO = hostname, no RCPT to third parties |
| SSRF via attacker-controlled MX/PTR/MTA-STS host | `netguard::outbound_allowed` on every resolved IP; curl pinned, https only, no redirects, size cap |
| Daemon restart loses runs | reports persisted as files; UI handles 404 |
| Monitoring noise | interval ≥60 min, kv cooldown, confirmation run, one summary message per monitor per cooldown |
| `exim.conf.local` vs cPanel's editor | markers + `.include_if_exists` (removing the file = kill switch), buildeximconf after every change, `EximHook.pm` already resyncs on rebuilds |
