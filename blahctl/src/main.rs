use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs, io};

use anyhow::{Context, Result};
use blah::bitflags;
use blah::types::{
    get_timestamp, ChatPayload, CreateRoomPayload, MemberPermission, RichText, RoomAttrs,
    RoomMember, RoomMemberList, ServerPermission, UserKey, WithSig,
};
use blah::uuid::Uuid;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH};
use rand::rngs::OsRng;
use reqwest::Url;
use rusqlite::{named_params, Connection};
use tokio::runtime::Runtime;

/// NB. Sync with docs of [`User::url`].
const KEY_URL_SUBPATH: &str = "/.well-known/blah/key";

/// Control or manage Blah Chat Server.
#[derive(Debug, clap::Parser)]
#[clap(about, version = option_env!("CFG_RELEASE").unwrap_or(env!("CARGO_PKG_VERSION")))]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Generate a keypair.
    GenerateKey {
        /// The output path to store secret key.
        #[arg(long, short)]
        output: PathBuf,
    },
    /// Database manipulation.
    Database {
        /// The path to the database.
        #[arg(long = "db")]
        database: PathBuf,

        #[command(subcommand)]
        command: DbCommand,
    },
    /// Access the API endpoint.
    Api {
        /// The URL to the API endpoint.
        #[arg(long)]
        url: Url,

        #[command(subcommand)]
        command: ApiCommand,
    },
}

#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
enum DbCommand {
    /// Create and initialize database.
    Init,
    /// Set user property, possibly adding new users.
    SetUser {
        #[command(flatten)]
        user: User,

        #[arg(long, value_parser = flag_parser::<ServerPermission>)]
        permission: ServerPermission,
    },
}

fn flag_parser<T: bitflags::Flags>(s: &str) -> clap::error::Result<T> {
    bitflags::parser::from_str_strict(s)
        .map_err(|_| clap::Error::new(clap::error::ErrorKind::InvalidValue))
}

#[derive(Debug, clap::Subcommand)]
enum ApiCommand {
    /// Create a room with the given user as the only owner.
    CreateRoom {
        #[arg(long, short = 'f')]
        private_key_file: PathBuf,

        #[arg(long)]
        title: String,

        #[arg(long, value_parser = flag_parser::<RoomAttrs>)]
        attrs: Option<RoomAttrs>,
    },
    PostChat {
        #[arg(long, short = 'f')]
        private_key_file: PathBuf,

        #[arg(long)]
        room: Uuid,

        #[arg(long)]
        text: String,
    },
}

// This should be an enum but clap does not support it on `Args` yet.
// See: https://github.com/clap-rs/clap/issues/2621
#[derive(Debug, clap::Args)]
#[clap(group = clap::ArgGroup::new("user").required(true).multiple(false))]
struct User {
    /// Hex-encoded public key.
    #[arg(long, group = "user", value_parser = userkey_parser)]
    key: Option<VerifyingKey>,

    /// Path to a user public key.
    #[arg(long, short = 'f', group = "user")]
    public_key_file: Option<PathBuf>,

    /// User's URL where `/.well-known/blah/key` is hosted.
    #[arg(long, group = "user")]
    url: Option<Url>,
}

fn userkey_parser(s: &str) -> clap::error::Result<VerifyingKey> {
    (|| {
        let mut buf = [0u8; PUBLIC_KEY_LENGTH];
        hex::decode_to_slice(s, &mut buf).ok()?;
        VerifyingKey::from_bytes(&buf).ok()
    })()
    .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::InvalidValue))
}

impl User {
    async fn fetch_key(&self) -> Result<UserKey> {
        let rawkey = if let Some(key) = &self.key {
            return Ok(UserKey(key.to_bytes()));
        } else if let Some(path) = &self.public_key_file {
            fs::read_to_string(path).context("failed to read key file")?
        } else if let Some(url) = &self.url {
            let url = url.join(KEY_URL_SUBPATH)?;
            reqwest::get(url).await?.error_for_status()?.text().await?
        } else {
            unreachable!()
        };
        let key = VerifyingKey::from_public_key_pem(&rawkey)
            .context("invalid key")?
            .to_bytes();
        Ok(UserKey(key))
    }
}

fn main() -> Result<()> {
    let cli = <Cli as clap::Parser>::parse();

    match cli.command {
        Command::GenerateKey { output } => {
            let privkey = SigningKey::generate(&mut OsRng);
            let pubkey_doc = privkey.verifying_key().to_public_key_pem(LineEnding::LF)?;
            privkey.write_pkcs8_pem_file(&output, LineEnding::LF)?;
            io::stdout().write_all(pubkey_doc.as_bytes())?;
        }
        Command::Database { database, command } => {
            use rusqlite::OpenFlags;

            let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
            flags.set(
                OpenFlags::SQLITE_OPEN_CREATE,
                matches!(command, DbCommand::Init),
            );
            let conn =
                Connection::open_with_flags(database, flags).context("failed to open database")?;
            main_db(conn, command)?;
        }
        Command::Api { url, command } => build_rt()?.block_on(main_api(url, command))?,
    }

    Ok(())
}

fn build_rt() -> Result<Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to initialize tokio runtime")
}

fn main_db(conn: Connection, command: DbCommand) -> Result<()> {
    match command {
        DbCommand::Init => {}
        DbCommand::SetUser { user, permission } => {
            let userkey = build_rt()?.block_on(user.fetch_key())?;

            conn.execute(
                r"
                INSERT
                INTO `user` (`userkey`, `permission`)
                VALUES (:userkey, :permission)
                ON CONFLICT (`userkey`) DO UPDATE SET
                    `permission` = :permission
                ",
                named_params! {
                    ":userkey": userkey,
                    ":permission": permission,
                },
            )?;
        }
    }
    Ok(())
}

fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let pem = fs::read_to_string(path).context("failed to read private key file")?;
    SigningKey::from_pkcs8_pem(&pem).context("failed to parse private key")
}

async fn main_api(api_url: Url, command: ApiCommand) -> Result<()> {
    let client = reqwest::Client::new();
    match command {
        ApiCommand::CreateRoom {
            private_key_file,
            title,
            attrs,
        } => {
            let key = load_signing_key(&private_key_file)?;
            let payload = CreateRoomPayload {
                attrs: attrs.unwrap_or_default(),
                title,
                // The CLI does not support passing multiple members because `User` itself is a
                // disjoint arg-group.
                members: RoomMemberList(vec![RoomMember {
                    permission: MemberPermission::ALL,
                    user: UserKey(key.verifying_key().to_bytes()),
                }]),
            };
            let payload = WithSig::sign(&key, get_timestamp(), &mut OsRng, payload)?;

            let ret = client
                .post(api_url.join("/room/create")?)
                .json(&payload)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            println!("{ret}");
        }
        ApiCommand::PostChat {
            private_key_file,
            room,
            text,
        } => {
            let key = load_signing_key(&private_key_file)?;
            let payload = ChatPayload {
                room,
                rich_text: RichText::from(text),
            };
            let payload = WithSig::sign(&key, get_timestamp(), &mut OsRng, payload)?;

            let ret = client
                .post(api_url.join(&format!("/room/{room}/item"))?)
                .json(&payload)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            println!("{ret}");
        }
    }

    Ok(())
}
