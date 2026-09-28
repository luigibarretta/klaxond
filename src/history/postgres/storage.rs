use anyhow::{Result, bail};
use postgres::Client;

mod migration;

pub(super) use migration::migrate;

pub(super) fn validate_schema(client: &mut Client) -> Result<()> {
    let row = client.query_one("SELECT to_regclass('klaxond_deliveries')::text", &[])?;
    let table: Option<String> = row.get(0);
    if table.is_none() {
        bail!("source postgres history does not contain klaxond_deliveries");
    }
    Ok(())
}
