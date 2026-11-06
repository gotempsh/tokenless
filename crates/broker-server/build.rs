// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rebuilds the binary when the console bundle changes, so a release build
//! made after `bun run build` always embeds the console it was built with.

fn main() {
    println!("cargo:rerun-if-changed=../../broker-ui/dist");
}
