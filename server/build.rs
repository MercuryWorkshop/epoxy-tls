use std::error::Error;

use vergen_git2::{Emitter, Git2Builder, RustcBuilder};

fn main() -> Result<(), Box<dyn Error>> {
	let rustc = RustcBuilder::default()
		.semver(true)
		.host_triple(true)
		.build()?;
	let git = Git2Builder::default().sha(true).dirty(true).build()?;
	Emitter::new()
		.add_instructions(&rustc)?
		.add_instructions(&git)?
		.emit()?;
	Ok(())
}
