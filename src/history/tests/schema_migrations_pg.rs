//! PostgreSQL half of the schema-runner adoption tests (suite `--ignored`,
//! KLAXOND_TEST_POSTGRES_URL). Each test works in a database of its own,
//! created and dropped here, because the previous release's dump addresses
//! the `public` schema.

use super::*;

const POSTGRES_FIXTURE: &str = include_str!("fixtures/pre_dual_db.pgdump");

/// A database created for one test and dropped (FORCE) on drop.
struct TempDatabase {
    admin_url: String,
    name: String,
    url: String,
}

impl TempDatabase {
    fn new(label: &str) -> Self {
        let admin_url = std::env::var("KLAXOND_TEST_POSTGRES_URL")
            .expect("KLAXOND_TEST_POSTGRES_URL is required for this ignored test");
        let name = format!(
            "kx_{label}_{}",
            crate::util::token_urlsafe(8).to_lowercase()
        );
        let name: String = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let (head, tail) = admin_url.rsplit_once('/').expect("database URL");
        let query = tail.find('?').map_or("", |index| &tail[index..]);
        let url = format!("{head}/{name}{query}");
        let mut admin = ::postgres::Client::connect(&admin_url, ::postgres::NoTls).unwrap();
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .unwrap();
        Self {
            admin_url,
            name,
            url,
        }
    }

    fn client(&self) -> ::postgres::Client {
        ::postgres::Client::connect(&self.url, ::postgres::NoTls).unwrap()
    }

    fn cfg(&self) -> HistoryConfig {
        HistoryConfig {
            backend: "postgres".into(),
            sqlite_path: PathBuf::from("/tmp/unused"),
            postgres_url: self.url.clone(),
            retention: 0,
            default_limit: 500,
        }
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        if let Ok(mut admin) = ::postgres::Client::connect(&self.admin_url, ::postgres::NoTls) {
            let _ = admin.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ));
        }
    }
}

/// The dump without psql meta-commands (`\restrict` / `\unrestrict`).
fn fixture_sql() -> String {
    POSTGRES_FIXTURE
        .lines()
        .filter(|line| !line.starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n")
}

fn postgres_rows(client: &mut ::postgres::Client) -> BTreeMap<String, Vec<String>> {
    let tables: Vec<String> = client
        .query(
            "SELECT table_name::text FROM information_schema.tables
              WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
              ORDER BY table_name",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    tables
        .into_iter()
        .filter(|table| table != LEDGER_TABLE)
        .map(|table| {
            let mut rows: Vec<String> = client
                .query(&format!("SELECT row_to_json(t)::text FROM {table} t"), &[])
                .unwrap()
                .iter()
                .map(|row| row.get(0))
                .collect();
            rows.sort();
            (table, rows)
        })
        .collect()
}

fn postgres_ledger(client: &mut ::postgres::Client) -> LedgerRows {
    client
        .query(
            &format!("SELECT version, name, checksum FROM {LEDGER_TABLE} ORDER BY version"),
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect()
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn postgres_history_of_the_previous_release_is_adopted_unchanged() {
    let database = TempDatabase::new("adopt");
    database.client().batch_execute(&fixture_sql()).unwrap();
    let mut client = database.client();
    client
        .batch_execute(&format!(
            "INSERT INTO {LEDGER_TABLE}(version) VALUES (5), (6), (7), (8)"
        ))
        .unwrap();
    let ddl = dual_db::postgres::ddl_fingerprint(&mut client, &options()).unwrap();
    let logical = dual_db::postgres::snapshot(&mut client, &options()).unwrap();
    let rows = postgres_rows(&mut client);
    assert_eq!(rows["klaxond_deliveries"].len(), 3);

    let report = super::super::postgres::migrate_postgres(&mut client).unwrap();
    assert_eq!(report.adopted, vec![BASELINE_VERSION]);
    assert!(report.applied.is_empty(), "nothing is applied as new");
    let again = super::super::postgres::migrate_postgres(&mut client).unwrap();
    assert!(again.applied.is_empty() && again.adopted.is_empty());
    let store = HistoryStore::open(&database.cfg()).unwrap();
    assert_eq!(store.deliveries_page(10, 0).unwrap().total, 3);
    drop(store);

    assert_eq!(
        dual_db::postgres::ddl_fingerprint(&mut client, &options()).unwrap(),
        ddl
    );
    assert_eq!(
        dual_db::postgres::snapshot(&mut client, &options()).unwrap(),
        logical
    );
    assert_eq!(postgres_rows(&mut client), rows);
    let checksum = super::super::postgres::postgres_migrations()[0].checksum();
    assert_eq!(postgres_ledger(&mut client), expected_ledger(checksum));
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn fresh_postgres_history_matches_the_previous_release_schema() {
    let legacy = TempDatabase::new("legacy");
    legacy.client().batch_execute(&fixture_sql()).unwrap();
    let fresh = TempDatabase::new("fresh");
    drop(HistoryStore::open(&fresh.cfg()).unwrap());
    assert_eq!(
        dual_db::postgres::ddl_fingerprint(&mut fresh.client(), &options()).unwrap(),
        dual_db::postgres::ddl_fingerprint(&mut legacy.client(), &options()).unwrap()
    );
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn sqlite_and_postgres_history_schemas_have_parity() {
    let database = TempDatabase::new("parity");
    let sqlite = rusqlite::Connection::open_in_memory().unwrap();
    dual_db::parity::migrate_and_compare(
        &sqlite,
        &super::super::sqlite::sqlite_migrations(),
        &mut database.client(),
        &super::super::postgres::postgres_migrations(),
        &crate::history::schema::ledger().unwrap(),
    )
    .unwrap();
}
