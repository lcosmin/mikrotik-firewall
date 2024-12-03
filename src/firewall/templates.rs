use anyhow::Result;
use minijinja::{Environment, Value};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{debug, error};

#[derive(Debug)]
pub struct Jinja<'a> {
    env: Environment<'a>,
}

impl<'a> Jinja<'a> {
    pub fn new(root_dir: &PathBuf) -> Result<Self> {
        let mut env = minijinja::Environment::new();

        let root_dir = root_dir.canonicalize()?;

        env.set_debug(true);
        //env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);

        //let root_path_clone = root_dir.clone();

        env.set_loader(move |name| -> Result<Option<String>, minijinja::Error> {
            debug!("jinja loading template: {}", &name);

            // Join paths, canonicalize and make sure they're under root_dir, otherwise error
            let template_name = Path::new(name);

            let template_path = root_dir.join(template_name);

            let template_path = match template_path.canonicalize() {
                Ok(x) => x,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => {
                    error!("error canonicalizing path: {}", e);
                    return Err(minijinja::Error::new(
                        minijinja::ErrorKind::InvalidOperation,
                        format!(
                            "invalid include path 1: {}",
                            &template_path.as_os_str().to_str().unwrap()
                        ),
                    ));
                }
            };

            if !template_path.starts_with(&root_dir) {
                return Err(minijinja::Error::new(
                    minijinja::ErrorKind::InvalidOperation,
                    format!("invalid include path 2: {:?}", &template_path),
                ));
            }

            match fs::read_to_string(template_path) {
                Ok(contents) => Ok(Some(contents)),
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(err) => Err(minijinja::Error::new(
                    minijinja::ErrorKind::TemplateNotFound,
                    "cannot find template",
                )
                .with_source(err)),
            }
        });

        env.add_template("m", include_str!("macros.jinja"))
            .expect("built-in macros.jinja");

        Ok(Jinja { env })
    }

    /// Expands the specified Jinja template
    pub fn expand_template(&self, context: &Value, template: &str) -> Result<String> {
        let tpl = self.env.template_from_named_str("temp", template)?;

        tpl.render(context).map_err(|x| anyhow::Error::new(x))
    }

    /// Loads a Jinja template from the specified file and expands it
    pub fn expand_template_from_file(&self, ctx: &Value, path: &PathBuf) -> Result<String> {
        let raw = fs::read_to_string(path)?;

        self.expand_template(ctx, &raw)
    }
}

#[cfg(test)]
mod tests {

    use super::Jinja;
    use assert2::check;
    use minijinja::context;
    use rstest::rstest;
    use std::path::{Path, PathBuf};

    use crate::firewall::testing::{jinja, test_dir};

    #[rstest]
    fn test_expand_template(jinja: Jinja<'_>) {
        let ctx = context! {
            foo => "bar",
        };

        let template = "Hello, {{ name }}".to_string();

        check!(jinja.expand_template(&ctx, &template).unwrap() == "Hello, ".to_string());

        let ctx = context! {
            name => "bar",
        };

        check!(jinja.expand_template(&ctx, &template).unwrap() == "Hello, bar".to_string());
    }

    #[rstest]
    fn test_expand_template_from_file(test_dir: PathBuf) {
        let jinja = Jinja::new(&test_dir).unwrap();

        let ctx = context! {};

        let template = test_dir.join(Path::new("unexisting"));

        let res = jinja.expand_template_from_file(&ctx, &template);
        check!(res.is_err());

        let template = test_dir.join(Path::new("example1.jinja"));

        let res = jinja.expand_template_from_file(&ctx, &template);
        check!(res.is_ok());

        check!(res.unwrap() == "Hello, !");
    }
}
