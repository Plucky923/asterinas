extern crate getopts;

use std::{env, fs, path::Path};

use getopts::Options;

const COPIED_DEP_EXTENSIONS: [&str; 3] = [".rlib", ".rmeta", ".so"];
fn copied_crate_name(file_name: &str) -> Option<&str> {
    let stem = COPIED_DEP_EXTENSIONS
        .into_iter()
        .find_map(|extension| file_name.strip_suffix(extension))?;
    let crate_name_with_hash = stem.strip_prefix("lib")?;

    Some(
        crate_name_with_hash
            .split_once('-')
            .map(|(crate_name, _)| crate_name)
            .unwrap_or(crate_name_with_hash),
    )
}

fn should_copy_dependency(file_name: &str) -> bool {
    copied_crate_name(file_name).is_some()
}

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    let mut opts = Options::new();
    opts.optmulti("i", "input", "input directory", "INPUT_DIR");
    opts.optmulti("", "input-host", "input host directory", "INPUT_HOST_DIR");
    opts.reqopt("", "output-deps", "output directory", "OUTPUT_DIR");
    opts.optopt("", "output-host-deps", "ignored", "OUTPUT_HOST_DIR");
    opts.optopt("", "output-sysroot", "ignored", "OUTPUT_SYSROOT_DIR");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => return Err(e.to_string()),
    };

    if matches.opt_present("h") {
        print!("{}", opts.usage("Usage: copy_build_deps [options]"));
        return Ok(());
    }

    let output_dir = matches.opt_str("output-deps").expect("missing output-deps");
    fs::create_dir_all(&output_dir).map_err(|e| format!("Failed to create output dir: {}", e))?;

    let mut input_dirs = matches.opt_strs("i");
    input_dirs.extend(matches.opt_strs("input-host"));

    for input_dir in input_dirs {
        let path = Path::new(&input_dir);
        if !path.exists() {
            continue;
        }

        for entry in
            fs::read_dir(path).map_err(|e| format!("Failed to read dir {}: {}", input_dir, e))?
        {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let file_name = match path.file_name() {
                Some(n) => n.to_string_lossy(),
                None => continue,
            };

            if !should_copy_dependency(&file_name) {
                continue;
            }

            let dest = Path::new(&output_dir).join(path.file_name().unwrap());
            fs::copy(&path, &dest)
                .map_err(|e| format!("Failed to copy {:?} to {:?}: {}", path, dest, e))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{copied_crate_name, should_copy_dependency};

    #[test]
    fn parses_dependency_file_names() {
        assert_eq!(
            copied_crate_name("libaster_framevisor-abc123.rlib"),
            Some("aster_framevisor")
        );
        assert_eq!(copied_crate_name("libspin-deadbeef.rmeta"), Some("spin"));
        assert_eq!(
            copied_crate_name("libproc_macro2-feedface.so"),
            Some("proc_macro2")
        );
        assert_eq!(copied_crate_name("framevm"), None);
    }

    #[test]
    fn copies_sysroot_and_non_sysroot_dependencies() {
        assert!(should_copy_dependency("libcore-abc123.rlib"));
        assert!(should_copy_dependency("liballoc-abc123.rmeta"));
        assert!(should_copy_dependency("libcompiler_builtins-abc123.rlib"));
        assert!(should_copy_dependency("libaster_framevisor-abc123.rlib"));
        assert!(should_copy_dependency("libspin-abc123.rmeta"));
    }
}
