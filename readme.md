# FoxOptimizer

**Role**: Static Analysis & Compilation Toolchain for Network Security Rules.  
**Language**: Python 3  
**Input**: Snort/Suricata Rule Files (`.rules`)  
**Output**: Optimized binary artifacts consumed by **FoxEngine** (C++ runtime).

---

## 1. Project Layout

```
optimizer/
├── main.py                 # Entry point. Orchestrates all 5 phases sequentially.
├── src/
│   ├── cleaner.py          # Phase 1: Rule filtering (stateful/complex keyword rejection).
│   ├── parser.py           # Phase 2: Snort syntax parser + variable resolution.
│   ├── models.py           # Data structures (RuleVector, Pattern).
│   ├── ip_engine.py        # Phase 3: Dimensional reduction (IP/Port merging).
│   ├── content_engine.py   # Phase 4: Semantic deduplication of content patterns.
│   └── exporter.py         # Phase 5: Artifact generation (patterns.txt, msgpack, firewall.sh).
├── inputs/                 # Source rule files (e.g. snort3-community.rules).
├── outputs/                # Generated artifacts.
│   ├── patterns.txt
│   ├── rules_config.msgpack
│   ├── firewall.sh
│   └── cleaned_baseline.rules
└── requirements.txt
```

---

## 2. Pipeline Overview

The optimizer operates as a 5-phase compilation pipeline. Each phase transforms the rule set, progressively reducing it from raw text to compact binary artifacts.

```
 Phase 1          Phase 2          Phase 3           Phase 4          Phase 5
┌─────────┐    ┌──────────┐    ┌─────────────┐    ┌───────────┐    ┌──────────┐
│ Cleaner │───▶│  Parser  │───▶│  IP Engine  │───▶│  Content  │───▶│ Exporter │
│         │    │          │    │             │    │  Engine   │    │          │
│ .rules  │    │ RuleVector│   │ Merge IPs   │    │ Dedup     │    │ 3 files  │
│ → clean │    │ objects   │   │ Merge Ports │    │ patterns  │    │ output   │
└─────────┘    └──────────┘    └─────────────┘    └───────────┘    └──────────┘

Input: snort3-community.rules (31,000+ lines)
Output: ~3100 optimized rules, ~4370 unique patterns
```

---

## 3. Phase Details

### 3.1 Phase 1 — Cleaning (`cleaner.py`)

Reads the raw `.rules` file line by line and makes a keep/reject decision for each rule.

**Rejection Criteria:**

| Category | Keywords | Reason |
|----------|----------|--------|
| Stateful | `flowbits`, `threshold`, `detection_filter`, `stream_size`, `tag`, `rate_filter` | Require cross-packet state memory that FoxEngine does not implement. |
| Complex Logic | `byte_test`, `byte_jump`, `byte_extract`, `ssl_state`, `dsize`, `isdataat` | Require arithmetic operations on payload that are outside the PoC scope. |
| Blacklisted SIDs | `sid:51642` | Blocks benign User-Agents (e.g. `curl`) used by test tools. |

**Output**: `cleaned_baseline.rules` — a filtered version containing only rules expressible by the FoxEngine (IP/Port + content/pcre patterns).

### 3.2 Phase 2 — Parsing (`parser.py`)

Parses each cleaned rule using a strict regex matching the Snort header format:
```
action proto src_ip src_port -> dst_ip dst_port (options)
```

**Variable Resolution:**
Standard Snort variables are resolved at parse time:
| Variable | Resolution |
|----------|------------|
| `$HOME_NET` | `192.168.0.0/16, 10.0.0.0/8` |
| `$EXTERNAL_NET` | `!$HOME_NET` (complement) |
| `$HTTP_PORTS` | `80` |
| `$HTTP_SERVERS` | `= $HOME_NET` |
| `any` | `0.0.0.0/0` (IP) or `0:65535` (port) |

In `--test-mode`, `$EXTERNAL_NET` resolves to `any` (required for internal CloudLab testing where attacker and target share the same subnet).

**IP/Port Representation:**
All IP addresses are stored as `netaddr.IPSet` objects, enabling efficient set operations (union, difference, intersection) during the merging phase. Ports use the same structure, abusing `IPRange(0, 65535)` as integer ranges.

**Option Parsing:**
The `_parse_options()` method extracts from the rule body:
- `content:"..."` → `Pattern(string_val=..., is_regex=False)`
- `pcre:"/.../flags"` → `Pattern(string_val=..., is_regex=True)`
- Content modifiers (`nocase`, `depth`, `offset`, `distance`, `within`, `fast_pattern`) are attached to the last `Pattern` object's `modifiers` dict.
- `flow:to_server,established` → `rule.direction`, `rule.established`
- `flags:S` → `rule.tcp_flags` (preserved to prevent merging SYN probes with normal traffic)
- `sid:NNN` → `rule.id`

**Output**: A list of `RuleVector` objects.

### 3.3 Phase 3 — Dimensional Reduction (`ip_engine.py`)

The IP Engine implements an iterative fixed-point merging algorithm called **Hypercube Convergence**.

**Step 1 — Segregation:**
Rules are split into two groups:
- **Pure Firewall** (`rule.patterns == []`): Rules that only check IP/Port (no content inspection needed). These will be offloaded to `iptables`.
- **Deep Inspection** (`rule.patterns != []`): Rules that require payload scanning via Hyperscan.

**Step 2 — Merging Loop (per group):**
The loop runs 4 merge passes per iteration:
1. **Merge Source IPs**: Rules sharing identical `(proto, dst_ip, src_port, dst_port, direction, action, patterns, tcp_flags)` are merged by taking the union of their `src_ip` sets.
2. **Merge Destination IPs**: Same, but merges `dst_ip` sets.
3. **Merge Destination Ports**: Same, but merges `dst_port` sets.
4. **Merge Source Ports**: Same, but merges `src_port` sets.

The loop repeats until the rule count stabilizes (fixed point). This typically converges in 2-3 iterations.

**Security Invariant:** The `tcp_flags`, `icmp_type`, and `icmp_code` fields are part of the merge signature. This prevents merging a SYN scan detection rule with general traffic rules.

**Output**: Two lists — `firewall_rules[]` and `inspection_rules[]`.

### 3.4 Phase 4 — Semantic Content Optimization (`content_engine.py`)

Operates only on `inspection_rules[]`:
1. **Exact Deduplication**: Rules with identical pattern sets are collapsed.
2. **Contextual Aggregation**: Rules sharing the same network context (proto, IP, ports) but different patterns are merged into a single rule with an OR pattern list (flagged with `_aggregated_or = True`).

Trie-based prefix factorization (e.g. `"GET /admin"` + `"GET /config"` → `"GET /(admin|config)"`) is implemented but **disabled** in the current version to avoid false positives from semantic mixing.

**Output**: `final_inspection_rules[]`.

### 3.5 Phase 5 — Export (`exporter.py`)

Generates the 3 artifact files consumed by FoxEngine.

#### 3.5.1 `patterns.txt` — Hyperscan Database

**Structure:** Two sections in a single file.

**Section 1 — Atomic Patterns:**
Each unique pattern across all rules is assigned a globally unique integer ID. Duplicate patterns (even from different rules) share the same ID.

Format: `ID:/regex/flags`

For `content:` patterns (literals), the string is `re.escape()`-d before emission. Snort hex sequences (`|XX XX|`) are converted to `\xHH` notation. PCRE patterns are sanitized (anchors `^$` removed, back-references rejected, lookahead/lookbehind rejected).

Flags: `i` = caseless, `s` = dotall, `m` = multiline, `H` = singlematch.

**Section 2 — Combinatorial Expressions:**
For rules with multiple patterns, a logical expression is emitted using Hyperscan's `HS_FLAG_COMBINATION` syntax:
- `100001:/(1 & 2 & 5)/c` — AND: All atomic patterns must match.
- `100002:/(3 | 7 | 12)/c` — OR: At least one atomic pattern must match (aggregated rules).

IDs in this section start at 100000 to avoid collision with atomic IDs.

**Important:** The C++ engine skips lines with flag `c` during Hyperscan compilation. These expressions are parsed separately and the AND/OR logic is evaluated in C++ after `hs_scan()` returns the list of matched atomic IDs.

#### 3.5.2 `rules_config.msgpack` — Binary Rule Logic

A MessagePack-serialized array. Each element is a map with these keys:

```
{
  "id":         uint32,       # Rule SID
  "proto":      string,       # "tcp" | "udp" | "icmp" | "ip"
  "src_ips":    [string],     # List of CIDR strings: ["10.0.0.0/8"]
  "dst_ips":    [string],     # List of CIDR strings
  "src_ports":  [[u16, u16]], # List of [start, end] ranges
  "dst_ports":  [[u16, u16]], # List of [start, end] ranges
  "direction":  string,       # "to_server" | "to_client" | "any"
  "hs_id":      uint32,       # Hyperscan pattern ID (0 = pure L3/L4, no scan needed)
  "atomic_ids": [uint32],     # For multi-pattern rules: list of atomic IDs
  "is_multi":   bool,         # true if rule has > 1 pattern
  "is_or":      bool,         # true = OR semantics (aggregated), false = AND (original Snort)
  "action":     string        # "alert" or "drop"
}
```

Pure firewall rules have `hs_id = 0`, `atomic_ids = []`, `is_multi = false`.

The C++ `Loader` deserializes this directly into `vector<RuleDefinition>` using msgpack-cxx's `MSGPACK_DEFINE_MAP` macro, then converts string CIDRs to binary `Cidr{network, mask}` structs and inserts each rule into the `CompositeRuleIndex`.

#### 3.5.3 `firewall.sh` — Kernel Offload Script

A generated Bash script that:
1. Creates a custom iptables chain `FOX_FILTER`.
2. For rules with > 3 source CIDRs, creates shared `ipset` hash:net sets to avoid iptables rule explosion.
3. Emits one `iptables -A FOX_FILTER ...` command per firewall rule, using `-m multiport --dports` for port lists (max 15 per rule, chunked automatically).
4. The script is `chmod 755` and can be run by the FoxEngine `Loader` at startup (currently disabled in test mode).

---

## 4. Data Model (`models.py`)

### RuleVector
The central data structure representing a parsed and optimized rule:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `int` | Rule SID |
| `original_text` | `str` | Raw rule text (or "FUSED ..." after merging) |
| `proto` | `str` | Protocol |
| `src_ips` | `netaddr.IPSet` | Source IP set |
| `dst_ips` | `netaddr.IPSet` | Destination IP set |
| `src_ports` | `netaddr.IPSet` | Source port ranges (abusing IPSet for integer ranges) |
| `dst_ports` | `netaddr.IPSet` | Destination port ranges |
| `direction` | `str` | Flow direction |
| `established` | `bool` | Requires established TCP connection |
| `tcp_flags` | `str or None` | TCP flags constraint (e.g. "S" for SYN) |
| `icmp_type` | `str or None` | ICMP type |
| `icmp_code` | `str or None` | ICMP code |
| `patterns` | `List[Pattern]` | Content/PCRE patterns |
| `action` | `str` | "alert" or "drop" |

### Pattern
| Field | Type | Description |
|-------|------|-------------|
| `string_val` | `str` | Pattern string |
| `is_regex` | `bool` | True for PCRE, False for literal content |
| `negated` | `bool` | Negated match |
| `modifiers` | `dict` | Snort modifiers (nocase, depth, offset, etc.) |

`Pattern` implements `__hash__` and `__eq__` (excluding internal keys prefixed with `_`) to enable deduplication via sets and dict keys.

---

## 5. Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Standard run
python3 main.py --rules snort3-community.rules

# Test mode (EXTERNAL_NET = any, for internal network testing)
python3 main.py --rules snort3-community.rules --test-mode
```

**Output:** All artifacts are written to `outputs/`.
