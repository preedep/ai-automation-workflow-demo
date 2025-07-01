mod infrastructure;

use log::info;

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    pretty_env_logger::init();
    info!("Hello, world!");
    Ok(())
}
