//! `cargo xtask devices`: build a container's device filter and show it.
//!
//! ```text
//! cargo xtask devices                  the defaults alone
//! cargo xtask devices --bundle DIR     a bundle's rules and devices, plus the defaults
//! cargo xtask devices --disasm         also print the eBPF program
//! ```
//!
//! Every rule is listed with where it came from; the ones the optimiser
//! dropped (because they can't change a decision) are marked.

use std::path::Path;

use rustlet_runtime::cgroups::devices::{Access, DeviceFilter, Origin, Rule};

pub(crate) fn run(bundle: Option<&Path>, show_disasm: bool) -> anyhow::Result<()> {
    let (what, filter) = match bundle {
        Some(dir) => {
            let bundle = rustlet_runtime::Bundle::load(dir)?;
            let plan = rustlet_runtime::plan::Plan::new("devices", &bundle)?;
            let filter = plan
                .cgroup
                .ok_or_else(|| anyhow::anyhow!("set linux.cgroupsPath to inspect the attached device filter"))?
                .devices;
            (format!("the device filter of {}", bundle.dir.display()), filter)
        }
        None => ("the default device filter".to_owned(), DeviceFilter::build(&[], &[])?),
    };
    println!("{what}");
    let row = |label: &str, value: String| println!("  {label:<13} {value}");
    let count = |f: fn(&Origin) -> bool| filter.rules.iter().filter(|r| f(&r.origin)).count();
    row(
        "rules",
        format!(
            "{} ({} from the spec, {} defaults, {} for creating linux.devices nodes)",
            filter.rules.len(),
            count(|o| matches!(o, Origin::Spec(_))),
            count(|o| matches!(o, Origin::Default)),
            count(|o| matches!(o, Origin::Node(_))),
        ),
    );
    row("compiled", format!("{} (the rest can't change a decision)", filter.compiled.len()));
    row(
        "starts with",
        (if filter.initial == Access::ALL {
            "everything allowed (after an `allow a *:* rwm`)"
        } else {
            "nothing allowed"
        })
        .to_owned(),
    );
    row("instructions", filter.program.len().to_string());
    println!();
    let kept = kept(&filter.rules, &filter.compiled);
    for (i, (rule, kept)) in filter.rules.iter().zip(kept).enumerate() {
        let from = match rule.origin {
            Origin::Spec(n) => format!("linux.resources.devices[{n}]"),
            Origin::Default => "default".to_owned(),
            Origin::Node(n) => format!("mknod of linux.devices[{n}]"),
        };
        let dropped = if kept { "" } else { "  (dropped)" };
        println!("  {i:3}  {:<24} {from}{dropped}", rule.to_string());
    }
    if show_disasm {
        println!();
        print!("{}", filter.disassemble());
    }
    Ok(())
}

/// Which of `rules` survived into `compiled` (a subsequence of it).
fn kept(rules: &[Rule], compiled: &[Rule]) -> Vec<bool> {
    let mut next = compiled.iter().peekable();
    rules.iter().map(|r| next.next_if(|c| *c == r).is_some()).collect()
}
