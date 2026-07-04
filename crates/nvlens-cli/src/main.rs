//! nvlens command-line interface.
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nvlens_core::{Catalog, Opened};

#[derive(Parser, Debug)]
#[command(name = "nvlens", about = "Visual novel resource extractor", version)]
struct Cli {
    /// Increase log verbosity (-v = debug, -vv = trace).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List the registered archive formats.
    Formats,
    /// Show the format an archive is recognized as, and its entry count.
    Info { archive: PathBuf },
    /// List the entries inside an archive.
    List { archive: PathBuf },
    /// Extract entries from an archive into a directory.
    Extract {
        archive: PathBuf,
        /// Output directory (defaults to ./<archive-name>_extracted).
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Only extract entries whose name contains this substring (case-insensitive).
        #[arg(short, long)]
        filter: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    nvlens_io::log::init(cli.verbose);
    register_formats();
    let catalog = Catalog::load();

    match cli.command {
        Command::Formats => cmd_formats(&catalog),
        Command::Info { archive } => cmd_info(&catalog, &archive),
        Command::List { archive } => cmd_list(&catalog, &archive),
        Command::Extract {
            archive,
            out,
            filter,
        } => cmd_extract(&catalog, &archive, out, filter.as_deref()),
    }
}

/// Links every format crate so their `register_*!` records are collected.
fn register_formats() {
    nvlens_archive::init();
    nvlens_image::init();
    nvlens_audio::init();
    nvlens_script::init();
    nvlens_video::init();
}

fn cmd_formats(catalog: &Catalog) -> Result<()> {
    println!("Registered archive formats:");
    for fmt in catalog.archive_formats() {
        let exts = fmt.extensions().join(", ");
        println!("  {:<12} {}  [{}]", fmt.tag(), fmt.description(), exts);
    }
    Ok(())
}

fn cmd_info(catalog: &Catalog, path: &Path) -> Result<()> {
    let opened = open(catalog, path)?;
    println!("File   : {}", path.display());
    println!(
        "Format : {} — {}",
        opened.format_tag, opened.format_description
    );
    println!("Entries: {}", opened.archive.entries().len());
    Ok(())
}

fn cmd_list(catalog: &Catalog, path: &Path) -> Result<()> {
    let opened = open(catalog, path)?;
    for entry in opened.archive.entries() {
        println!(
            "{:>10}  {:<8}  {}",
            entry.size,
            format!("{:?}", entry.kind),
            entry.name
        );
    }
    Ok(())
}

fn cmd_extract(
    catalog: &Catalog,
    path: &Path,
    out: Option<PathBuf>,
    filter: Option<&str>,
) -> Result<()> {
    let opened = open(catalog, path)?;
    let out_dir = out.unwrap_or_else(|| default_out_dir(path));
    let filter_lc = filter.map(str::to_ascii_lowercase);

    let mut extracted = 0usize;
    let mut failed = 0usize;
    for entry in opened.archive.entries() {
        if let Some(f) = &filter_lc {
            if !entry.name.to_ascii_lowercase().contains(f.as_str()) {
                continue;
            }
        }
        match extract_one(&*opened.archive, entry, &out_dir) {
            Ok(dest) => {
                println!("extract {}", dest.display());
                extracted += 1;
            }
            Err(e) => {
                // A single failed entry must not abort the whole archive.
                eprintln!("skip {}: {:#}", entry.name, e);
                failed += 1;
            }
        }
    }
    println!("done: {extracted} extracted, {failed} failed");
    Ok(())
}

fn extract_one(
    archive: &dyn nvlens_core::Archive,
    entry: &nvlens_core::Entry,
    out_dir: &Path,
) -> Result<PathBuf> {
    let rel = sanitize_relative(&entry.name)
        .with_context(|| format!("invalid entry name: {}", entry.name))?;
    let dest = out_dir.join(rel);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = archive.open_entry(entry)?;
    fs::write(&dest, &data)?;
    Ok(dest)
}

fn open(catalog: &Catalog, path: &Path) -> Result<Opened> {
    match catalog
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?
    {
        Some(opened) => Ok(opened),
        None => bail!("unrecognized archive format: {}", path.display()),
    }
}

fn default_out_dir(archive: &Path) -> PathBuf {
    let stem = archive
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("out");
    PathBuf::from(format!("{stem}_extracted"))
}

/// Turns an in-archive entry name into a safe relative path: normalizes
/// separators, strips drive letters / leading separators, and rejects `..`.
fn sanitize_relative(name: &str) -> Option<PathBuf> {
    let mut path = PathBuf::new();
    for part in name.split(['/', '\\']) {
        match part {
            "" | "." => continue,
            ".." => return None,
            p if p.contains(':') => return None,
            p => path.push(p),
        }
    }
    if path.as_os_str().is_empty() {
        None
    } else {
        Some(path)
    }
}
