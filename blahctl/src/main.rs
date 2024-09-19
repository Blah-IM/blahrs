use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{ensure, Context, Result};
use blah_types::identity::{IdUrl, UserActKeyDesc, UserIdentityDesc, UserProfile};
use blah_types::{
    bitflags, get_timestamp, ChatPayload, CreateGroup, CreateRoomPayload, Id, PubKey, RichText,
    RoomAttrs, ServerPermission, Signed,
};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey};
use ed25519_dalek::{SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH};
use humantime::Duration;
use rand::rngs::OsRng;
use rand::thread_rng;
use reqwest::Url;
use rusqlite::{named_params, Connection};
use tokio::runtime::Runtime;

/// NB. Sync with docs of [`User::url`].
// FIXME: Remove old interface.
const KEY_URL_SUBPATH: &str = "/.well-known/blah/key";

const USER_AGENT: &str = concat!("blahctl/", env!("CARGO_PKG_VERSION"));

/// Control or manage Blah Chat Server.
#[derive(Debug, clap::Parser)]
#[clap(about, version = option_env!("CFG_RELEASE").unwrap_or(env!("CARGO_PKG_VERSION")))]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Identity management.
    Identity {
        #[command(subcommand)]
        command: IdCommand,
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
enum IdCommand {
    /// Generate a new identity keypair.
    Generate {
        /// The identity description JSON file to write.
        #[arg(long, short = 'f')]
        desc_file: PathBuf,

        /// The output path to save the generated signing (private) key.
        /// Keep it secret and safe!
        #[arg(long)]
        id_key_file: PathBuf,

        /// The URL where the identity description is hosted on.
        ///
        /// It must be a domain with top-level path `/`. It should have HTTPS schema.
        /// The identity description file should be available at
        /// `<id_url>/.well-known/blah/identity.json`.
        #[arg(long)]
        id_url: IdUrl,
    },
    /// Validate identity description from a JSON file or URL.
    Validate {
        #[command(flatten)]
        id_desc_args: IdDescArgs,
    },
    /// Add an action subkey to an existing identity description.
    AddActKey {
        /// The identity description JSON file to modify.
        #[arg(long, short = 'f')]
        desc_file: PathBuf,

        /// The identity signing (private) key to sign with.
        #[arg(long)]
        id_key_file: PathBuf,

        /// The verifying (public) key of the action subkey to add.
        #[arg(long)]
        act_key: PubKey,

        /// The valid duration for the new subkey, starting from now.
        #[arg(long)]
        expire: Duration,

        /// Comment for the new subkey.
        #[arg(long)]
        comment: Option<String>,
    },
    /// Update profile of an existing identity description.
    ///
    /// The profile will be signed using the primary key.
    UpdateProfile {
        /// The identity description JSON file to modify.
        #[arg(long, short = 'f')]
        desc_file: PathBuf,

        /// The output path to save the generated signing (private) key.
        /// Keep it secret and safe!
        #[arg(long)]
        id_key_file: PathBuf,

        /// Valid id_url. Multiple URLs are allowed.
        /// If none are given, the previous URLs are used unchanged.
        #[arg(long)]
        id_url: Vec<IdUrl>,

        /// Preferred chat server URLs. Multiple URLs are allowed.
        /// If none are given, the previous URLs are used unchanged.
        #[arg(long)]
        preferred_chat_server_urls: Vec<Url>,

        /// Clear preferred chat servers list.
        #[arg(long, conflicts_with = "preferred_chat_server_urls")]
        clear_chat_server_urls: bool,
    },
}

#[derive(Debug, clap::Args)]
#[group(required = true, multiple = false)]
struct IdDescArgs {
    /// The identity URL to check.
    ///
    /// It should be a HTTPS domain with a top-level path `/`.
    #[arg(long)]
    id_url: Option<IdUrl>,

    /// The identity description JSON path to check.
    #[arg(long, short = 'f')]
    desc_file: Option<PathBuf>,
}

impl IdDescArgs {
    fn load(&self, rt: &Runtime) -> Result<UserIdentityDesc> {
        const LARGE_BODY_SIZE: usize = 64 << 10; // 64KiB

        let text = if let Some(url) = &self.id_url {
            if url.scheme() == "http" {
                // TODO: Verbosity control.
                eprintln!("warning: id_url has scheme http, which will be rejected by most server");
            }
            if url.port().is_some() {
                eprintln!("warning: id_url has custom port, which will be rejected by most server");
            }

            let url = url
                .join(UserIdentityDesc::WELL_KNOWN_PATH)
                .expect("IdUrl must be a valid base");
            rt.block_on(async {
                anyhow::Ok(
                    build_client()?
                        .get(url.clone())
                        .send()
                        .await?
                        .error_for_status()?
                        .text()
                        .await?,
                )
            })
            .with_context(|| format!("failed to GET {url}"))?
        } else if let Some(path) = &self.desc_file {
            fs::read_to_string(path).context("failed to read from desc_file")?
        } else {
            unreachable!("enforced by clap");
        };

        if text.len() > LARGE_BODY_SIZE {
            eprintln!(
                "warning: large description size ({}KiB), which will be rejected by most server",
                LARGE_BODY_SIZE >> 10,
            );
        }

        serde_json::from_str(&text).context("failed to parse identity description")
    }
}

#[derive(Debug, clap::Subcommand)]
enum DbCommand {
    /// Create and initialize database.
    Init,
    /// Set user property, possibly adding new users.
    SetUser {
        #[command(flatten)]
        user: Box<User>,

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
        room: i64,

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
    async fn fetch_key(&self) -> Result<PubKey> {
        let rawkey = if let Some(key) = &self.key {
            return Ok(PubKey(key.to_bytes()));
        } else if let Some(path) = &self.public_key_file {
            fs::read_to_string(path).context("failed to read key file")?
        } else if let Some(url) = &self.url {
            let url = url.join(KEY_URL_SUBPATH)?;
            build_client()?
                .get(url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?
        } else {
            unreachable!()
        };
        let key = VerifyingKey::from_public_key_pem(&rawkey)
            .context("invalid key")?
            .to_bytes();
        Ok(PubKey(key))
    }
}

fn main() -> Result<()> {
    let cli = <Cli as clap::Parser>::parse();

    match cli.command {
        Command::Identity { command } => main_id(command)?,
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

fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build HTTP client")
}

fn main_id(cmd: IdCommand) -> Result<()> {
    match cmd {
        IdCommand::Generate {
            desc_file,
            id_key_file,
            id_url,
        } => {
            let rng = &mut thread_rng();
            let id_key_priv = SigningKey::generate(rng);
            let id_key = PubKey(id_key_priv.verifying_key().to_bytes());

            let act_key_desc = UserActKeyDesc {
                act_key: id_key.clone(),
                expire_time: i64::MAX as _,
                comment: "id_key".into(),
            };
            let act_key_desc =
                Signed::sign(&id_key, &id_key_priv, get_timestamp(), rng, act_key_desc)?;
            let profile = UserProfile {
                preferred_chat_server_urls: Vec::new(),
                id_urls: vec![id_url],
            };
            let profile = Signed::sign(&id_key, &id_key_priv, get_timestamp(), rng, profile)?;
            let id_desc = UserIdentityDesc {
                id_key,
                act_keys: vec![act_key_desc],
                profile,
            };
            let id_desc_str = serde_json::to_string_pretty(&id_desc).unwrap();

            id_key_priv
                .write_pkcs8_pem_file(&id_key_file, LineEnding::LF)
                .context("failed to save private key")?;
            fs::write(desc_file, &id_desc_str).context("failed to save identity description")?;
        }
        IdCommand::Validate { id_desc_args } => {
            let id_desc = id_desc_args.load(&build_rt()?)?;
            id_desc.verify(id_desc_args.id_url.as_ref(), get_timestamp())?;
        }
        IdCommand::UpdateProfile {
            desc_file,
            id_key_file,
            id_url,
            preferred_chat_server_urls,
            clear_chat_server_urls,
        } => {
            let id_desc = fs::read_to_string(&desc_file).context("failed to open desc_file")?;
            let mut id_desc = serde_json::from_str::<UserIdentityDesc>(&id_desc)
                .context("failed to parse desc_file")?;
            let id_key_priv = load_signing_key(&id_key_file)?;
            let id_key = PubKey(id_key_priv.verifying_key().to_bytes());
            // TODO: Dedup this check.
            ensure!(id_key == id_desc.id_key, "id_key mismatch with key file");
            ensure!(
                id_desc
                    .act_keys
                    .iter()
                    .any(|kdesc| kdesc.signee.payload.act_key == id_key),
                "id_key must be one of the act_key",
            );

            let mut profile = id_desc.profile.signee.payload;
            if !id_url.is_empty() {
                profile.id_urls = id_url;
            }
            if clear_chat_server_urls {
                profile.preferred_chat_server_urls.clear();
            } else if !preferred_chat_server_urls.is_empty() {
                profile.preferred_chat_server_urls = preferred_chat_server_urls;
            }
            id_desc.profile = Signed::sign(
                &id_key,
                &id_key_priv,
                get_timestamp(),
                &mut thread_rng(),
                profile,
            )?;

            let id_desc_str = serde_json::to_string_pretty(&id_desc).unwrap();
            fs::write(desc_file, &id_desc_str).context("failed to save identity description")?;
        }
        IdCommand::AddActKey {
            desc_file,
            id_key_file,
            act_key,
            expire,
            comment,
        } => {
            let id_desc = fs::read_to_string(&desc_file).context("failed to open desc_file")?;
            let mut id_desc = serde_json::from_str::<UserIdentityDesc>(&id_desc)
                .context("failed to parse desc_file")?;
            let id_key_priv = load_signing_key(&id_key_file)?;
            let id_key = PubKey(id_key_priv.verifying_key().to_bytes());
            ensure!(id_key == id_desc.id_key, "id_key mismatch with key file");
            let exists = id_desc
                .act_keys
                .iter()
                .any(|kdesc| kdesc.signee.payload.act_key == act_key);
            ensure!(!exists, "duplicated act_key");

            let expire_time: i64 = SystemTime::now()
                .checked_add(*expire)
                .and_then(|time| {
                    time.duration_since(SystemTime::UNIX_EPOCH)
                        .ok()?
                        .as_secs()
                        .try_into()
                        .ok()
                })
                .context("invalid expire time")?;

            let rng = &mut thread_rng();
            let act_key_desc = UserActKeyDesc {
                act_key,
                expire_time: expire_time as _,
                comment: comment.unwrap_or_default(),
            };
            let act_key_desc =
                Signed::sign(&id_key, &id_key_priv, get_timestamp(), rng, act_key_desc)?;
            id_desc.act_keys.push(act_key_desc);

            let id_desc_str = serde_json::to_string_pretty(&id_desc).unwrap();
            fs::write(desc_file, &id_desc_str).context("failed to save identity description")?;
        }
    }
    Ok(())
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
            let payload = CreateRoomPayload::Group(CreateGroup {
                attrs: attrs.unwrap_or_default(),
                title,
            });
            // FIXME: Same key.
            let payload = Signed::sign(
                &PubKey(key.to_bytes()),
                &key,
                get_timestamp(),
                &mut OsRng,
                payload,
            )?;

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
                room: Id(room),
                rich_text: RichText::from(text),
            };
            // FIXME: Same key.
            let payload = Signed::sign(
                &PubKey(key.to_bytes()),
                &key,
                get_timestamp(),
                &mut OsRng,
                payload,
            )?;

            let ret = client
                .post(api_url.join(&format!("/room/{room}/msg"))?)
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
