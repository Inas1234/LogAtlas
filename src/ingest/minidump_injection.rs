use std::collections::{HashMap, HashSet};

use crate::model::{InjectedRegion, ModuleInfo, ProcessExecArtifact, Severity, ThreadInfo};

pub fn detect_injected_regions(
    dump: &minidump::Minidump<Vec<u8>>,
    modules: &[ModuleInfo],
    threads: &[ThreadInfo],
    exec_artifacts: &[ProcessExecArtifact],
) -> Vec<InjectedRegion> {
    let module_ranges: Vec<(u64, u64)> = modules
        .iter()
        .map(|m| (m.base, m.base.saturating_add(m.size)))
        .collect();

    let Ok(meminfo) = dump.get_stream::<minidump::MinidumpMemoryInfoList>() else {
        // Fallback: we can still flag thread entrypoints that start outside any loaded module.
        let mut by_start: HashMap<u64, Vec<String>> = HashMap::new();
        for t in threads {
            let Some(start) = t.start_address else {
                continue;
            };
            if addr_in_any(&module_ranges, start) {
                continue;
            }
            by_start.entry(start).or_default().push(format!(
                "thread start outside modules: tid=0x{:X} start=0x{:016X}",
                t.thread_id, start
            ));
        }

        let mut out: Vec<InjectedRegion> = by_start
            .into_iter()
            .map(|(start, reasons)| InjectedRegion {
                base: start,
                size: 0,
                protection: "unknown (MemoryInfoListStream missing)".into(),
                ty: "unknown".into(),
                state: "unknown".into(),
                reasons,
                risk: Severity::High,
            })
            .collect();
        out.sort_by_key(|r| (risk_rank(r.risk), r.base));
        return out;
    };

    struct Accum {
        size: u64,
        prot_bits: u32,
        ty_bits: u32,
        state_bits: u32,
        reasons: Vec<String>,
        risk: Severity,
        seen_region_bases: HashSet<u64>,
    }

    impl Default for Accum {
        fn default() -> Self {
            Self {
                size: 0,
                prot_bits: 0,
                ty_bits: 0,
                state_bits: 0,
                reasons: Vec::new(),
                risk: Severity::Warning,
                seen_region_bases: HashSet::new(),
            }
        }
    }

    let mut acc: HashMap<u64, Accum> = HashMap::new();

    for region in meminfo.iter() {
        // We focus on committed private pages with executable protection that do not overlap
        // a loaded module. This is a common shape for injected code/shellcode or JIT output.
        let committed = region
            .state
            .contains(minidump::format::MemoryState::MEM_COMMIT);
        if !committed {
            continue;
        }

        let is_private = region
            .ty
            .contains(minidump::format::MemoryType::MEM_PRIVATE);
        if !is_private {
            continue;
        }

        let exec = is_executable(region.protection);
        if !exec {
            continue;
        }

        let base = region.raw.base_address;
        let size = region.raw.region_size;
        if overlaps_any(&module_ranges, base, size) {
            continue;
        }

        let alloc_base = region.raw.allocation_base;
        let e = acc.entry(alloc_base).or_insert_with(|| Accum {
            risk: Severity::Warning,
            ..Default::default()
        });

        if e.seen_region_bases.insert(base) {
            e.size = e.size.saturating_add(size);
        }
        e.prot_bits |= region.raw.protection;
        e.ty_bits |= region.raw._type;
        e.state_bits |= region.raw.state;

        push_reason_once(
            &mut e.reasons,
            "committed private executable memory not backed by a module".into(),
        );

        if is_rwx(region.protection) {
            e.risk = Severity::High;
            push_reason_once(&mut e.reasons, "RWX protection".into());
        }
    }

    // Thread entrypoints are a strong pivot: if a thread starts outside any loaded module and
    // in a private executable allocation, that looks like classic injection (CreateRemoteThread).
    for t in threads {
        let Some(start) = t.start_address else {
            continue;
        };
        if addr_in_any(&module_ranges, start) {
            continue;
        }
        let Some(mi) = meminfo.memory_info_at_address(start) else {
            continue;
        };
        let alloc_base = mi.raw.allocation_base;

        let e = acc.entry(alloc_base).or_insert_with(|| Accum {
            risk: Severity::High,
            ..Default::default()
        });

        e.prot_bits |= mi.raw.protection;
        e.ty_bits |= mi.raw._type;
        e.state_bits |= mi.raw.state;
        if e.seen_region_bases.insert(mi.raw.base_address) {
            e.size = e.size.saturating_add(mi.raw.region_size);
        }

        e.risk = Severity::High;
        e.reasons.push(format!(
            "thread start outside modules: tid=0x{:X} start=0x{:016X}",
            t.thread_id, start
        ));
    }

    // If we recovered command-line strings at addresses inside a suspicious allocation, add that as context.
    for a in exec_artifacts {
        let Some(addr) = a.address else { continue };
        if addr_in_any(&module_ranges, addr) {
            continue;
        }
        let Some(mi) = meminfo.memory_info_at_address(addr) else {
            continue;
        };
        let alloc_base = mi.raw.allocation_base;
        let e = acc.entry(alloc_base).or_insert_with(|| Accum {
            risk: Severity::Warning,
            ..Default::default()
        });

        e.prot_bits |= mi.raw.protection;
        e.ty_bits |= mi.raw._type;
        e.state_bits |= mi.raw.state;
        if e.seen_region_bases.insert(mi.raw.base_address) {
            e.size = e.size.saturating_add(mi.raw.region_size);
        }

        push_reason_once(
            &mut e.reasons,
            "recovered execution artifact string points into this allocation".into(),
        );
    }

    let mut out: Vec<InjectedRegion> = acc
        .into_iter()
        .map(|(base, a)| InjectedRegion {
            base,
            size: a.size,
            protection: format!(
                "{:?}",
                minidump::format::MemoryProtection::from_bits_truncate(a.prot_bits)
            ),
            ty: format!(
                "{:?}",
                minidump::format::MemoryType::from_bits_truncate(a.ty_bits)
            ),
            state: format!(
                "{:?}",
                minidump::format::MemoryState::from_bits_truncate(a.state_bits)
            ),
            reasons: a.reasons,
            risk: a.risk,
        })
        .collect();

    out.sort_by_key(|r| (risk_rank(r.risk), std::cmp::Reverse(r.size), r.base));
    out
}

fn risk_rank(s: Severity) -> u8 {
    match s {
        Severity::High => 0,
        Severity::Warning => 1,
        Severity::Info => 2,
    }
}

fn is_executable(p: minidump::format::MemoryProtection) -> bool {
    use minidump::format::MemoryProtection as MP;
    p.intersects(
        MP::PAGE_EXECUTE
            | MP::PAGE_EXECUTE_READ
            | MP::PAGE_EXECUTE_READWRITE
            | MP::PAGE_EXECUTE_WRITECOPY,
    )
}

fn is_rwx(p: minidump::format::MemoryProtection) -> bool {
    use minidump::format::MemoryProtection as MP;
    p.contains(MP::PAGE_EXECUTE_READWRITE)
}

fn overlaps_any(ranges: &[(u64, u64)], base: u64, size: u64) -> bool {
    let end = base.saturating_add(size);
    for &(s, e) in ranges {
        if base < e && end > s {
            return true;
        }
    }
    false
}

fn addr_in_any(ranges: &[(u64, u64)], addr: u64) -> bool {
    for &(s, e) in ranges {
        if addr >= s && addr < e {
            return true;
        }
    }
    false
}

fn push_reason_once(reasons: &mut Vec<String>, reason: String) {
    if reasons.iter().any(|r| r == &reason) {
        return;
    }
    reasons.push(reason);
}
