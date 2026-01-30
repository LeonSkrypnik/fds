mod container;
mod crypto;
mod fsmeta;

use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "vault", version, about = "Encrypted container vault (MVP)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault file
    Init {
        #[arg(long)]
        path: String,
        #[arg(long)]
        password: String,
        /// Argon2 memory cost in KiB (e.g. 262144 = 256 MiB)
        #[arg(long, default_value_t = 131072)]
        m_cost_kib: u32,
        /// Argon2 time cost (iterations)
        #[arg(long, default_value_t = 3)]
        t_cost: u32,
    },

    /// List children of a directory id (default: root)
    Ls {
        #[arg(long)]
        path: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value_t = 1)]
        dir_id: u64,
    },

    /// Create directory
    Mkdir {
        #[arg(long)]
        path: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value_t = 1)]
        parent_id: u64,
        #[arg(long)]
        name: String,
    },

    /// Import a file from OS into vault
    Import {
        #[arg(long)]
        path: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        os_path: PathBuf,
        #[arg(long, default_value_t = 1)]
        parent_id: u64,
        #[arg(long)]
        name: Option<String>,
    },

    /// Export a file from vault to OS
    Export {
        #[arg(long)]
        path: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        file_id: u64,
        #[arg(long)]
        out_path: PathBuf,
    },

    /// Rename node by id
    Rename {
        #[arg(long)]
        path: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        id: u64,
        #[arg(long)]
        new_name: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Init {
            path,
            password,
            m_cost_kib,
            t_cost,
        } => {
            container::create_vault(&path, &password, m_cost_kib, t_cost)?;
            println!("Created vault: {path}");
        }

        Cmd::Ls {
            path,
            password,
            dir_id,
        } => {
            let sess = container::open_vault(&path, &password)?;
            let children = sess.meta.children_of(dir_id);
            for n in children {
                let t = match n.node_type {
                    fsmeta::NodeType::Dir => "DIR ",
                    fsmeta::NodeType::File => "FILE",
                };
                println!("{t}  id={}  parent={}  name={}", n.id, n.parent_id, n.name);
            }
        }

        Cmd::Mkdir {
            path,
            password,
            parent_id,
            name,
        } => {
            let mut sess = container::open_vault(&path, &password)?;
            let id = sess.meta.mkdir(parent_id, name)?;
            container::save_metadata(&sess, &password)?;
            println!("mkdir id={id}");
        }

        Cmd::Import {
            path,
            password,
            os_path,
            parent_id,
            name,
        } => {
            let mut sess = container::open_vault(&path, &password)?;
            let id = container::import_file(&mut sess, &password, &os_path, parent_id, name)?;
            println!("imported file id={id}");
        }

        Cmd::Export {
            path,
            password,
            file_id,
            out_path,
        } => {
            let sess = container::open_vault(&path, &password)?;
            container::export_file(&sess, file_id, &out_path)
                .with_context(|| format!("export id={file_id} -> {}", out_path.display()))?;
            println!("exported");
        }

        Cmd::Rename {
            path,
            password,
            id,
            new_name,
        } => {
            let mut sess = container::open_vault(&path, &password)?;
            sess.meta.rename(id, new_name)?;
            container::save_metadata(&sess, &password)?;
            println!("renamed");
        }
    }

    Ok(())
}