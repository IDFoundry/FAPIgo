//! The huskarl interop legs, each reporting pass or fail on its own. The
//! runner (interop/run-huskarl.sh) has already started conformance-as and
//! written this run's configuration into the work directory.
//!
//!     fapigo-interop-huskarl <work-dir>
mod harness;
mod legs;

use std::{
    future::Future,
    path::{MAIN_SEPARATOR, PathBuf},
    pin::Pin,
    process::ExitCode,
    time::Instant,
};

use harness::{Result, Run};

type Leg = for<'a> fn(&'a Run) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>>;

const LEGS: [(&str, Leg); 4] = [
    (
        "1 authorization code + PAR + PKCE + private_key_jwt + DPoP, UserInfo, resource, refresh",
        |run| Box::pin(legs::authorization_code_dpop(run)),
    ),
    (
        "2 authorization code + self_signed_tls_client_auth + certificate-bound tokens (mTLS aliases)",
        |run| Box::pin(legs::authorization_code_mtls(run)),
    ),
    (
        "3 message signing: JAR via PAR + JARM + private_key_jwt + DPoP",
        |run| Box::pin(legs::message_signing(run)),
    ),
    (
        "4 client_credentials + private_key_jwt + DPoP, resource",
        |run| Box::pin(legs::client_credentials(run)),
    ),
];

/// Legs interop/openid-client runs that huskarl's released API can't.
const SKIPPED: [(&str, &str); 2] = [
    (
        "5 CIBA poll",
        "no CIBA grant in the pinned huskarl release (poll mode is unreleased upstream)",
    ),
    ("6 CIBA ping", "huskarl implements no CIBA ping mode"),
];

/// The work directory setup.mjs wrote into: the runner's `mktemp -d`
/// directory, passed as the first argument. Anything that doesn't resolve
/// to a directory inside the system temporary directory is refused, as
/// interop/openid-client/lib/workdir.mjs does.
fn work_dir() -> Result<PathBuf> {
    let arg = std::env::args_os()
        .nth(1)
        .ok_or("usage: fapigo-interop-huskarl <work-dir>")?;
    let root = std::env::temp_dir().canonicalize()?;
    let dir = PathBuf::from(arg).canonicalize()?;
    let inside = dir
        .to_str()
        .zip(root.to_str())
        .is_some_and(|(dir, root)| dir.starts_with(&format!("{root}{MAIN_SEPARATOR}")));
    if !dir.is_dir() || !inside {
        return Err(format!(
            "work directory {} is not inside {}",
            dir.display(),
            root.display()
        )
        .into());
    }
    Ok(dir)
}

#[tokio::main]
async fn main() -> ExitCode {
    let run = match work_dir().and_then(|dir| Run::load(&dir)) {
        Ok(run) => run,
        Err(error) => {
            eprintln!("huskarl interop: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = 0;
    for (name, leg) in LEGS {
        let started = Instant::now();
        let outcome = leg(&run).await;
        let elapsed = started.elapsed().as_millis();
        match outcome {
            Ok(()) => println!("ok - {name} ({elapsed} ms)"),
            Err(error) => {
                failed += 1;
                println!("not ok - {name} ({elapsed} ms)");
                println!("    {error}");
                let mut source = error.source();
                while let Some(cause) = source {
                    println!("    caused by: {cause}");
                    source = cause.source();
                }
            }
        }
    }
    for (name, reason) in SKIPPED {
        println!("skip - {name}: {reason}");
    }
    println!(
        "huskarl interop: {} passed, {failed} failed, {} skipped",
        LEGS.len() - failed,
        SKIPPED.len()
    );
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
