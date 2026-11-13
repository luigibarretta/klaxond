use super::*;

#[test]
fn transaction_control_statements_are_refused() {
    for sql in [
        "COMMIT",
        "CREATE TABLE a (x INT); COMMIT;",
        "begin; CREATE TABLE a (x INT)",
        "CREATE TABLE a (x INT);\nrollback;",
        "SAVEPOINT s; CREATE TABLE a (x INT); RELEASE s",
        "END",
        "START TRANSACTION",
        "ABORT",
        "-- note\nCOMMIT",
        "/* a; */ BEGIN IMMEDIATE",
        "CREATE TRIGGER t AFTER INSERT ON a BEGIN SELECT 1; END; COMMIT",
    ] {
        assert!(
            matches!(
                reject_transaction_control(sql),
                Err(Error::InvalidRegistry(_))
            ),
            "{sql}"
        );
    }
}

#[test]
fn keywords_inside_bodies_strings_and_comments_are_fine() {
    for sql in [
        "CREATE TABLE a (x INT); CREATE INDEX i ON a(x);",
        "INSERT INTO a VALUES ('COMMIT; BEGIN'); UPDATE a SET x = 1",
        "CREATE TABLE \"commit\" (x INT)",
        "-- COMMIT here is a comment\nCREATE TABLE a (x INT)",
        "/* ROLLBACK; */ CREATE TABLE a (x INT)",
        "CREATE TRIGGER t AFTER INSERT ON a BEGIN UPDATE b SET y = 1; DELETE FROM c; END;",
        "CREATE TEMP TRIGGER IF NOT EXISTS t BEFORE DELETE ON a BEGIN SELECT 1; END",
        "DO $$ BEGIN PERFORM 1; END $$; CREATE TABLE a (x INT)",
        "CREATE FUNCTION f() RETURNS int AS $body$ BEGIN RETURN 1; END; $body$ LANGUAGE plpgsql",
        "SELECT CASE WHEN x THEN 1 END FROM a",
        "SELECT $1::int; SELECT 'it''s; COMMIT'",
        "UPDATE t SET last_seen_at = 1 WHERE 1 = 1",
        "",
    ] {
        assert!(reject_transaction_control(sql).is_ok(), "{sql}");
    }
}

#[test]
fn registry_validation_applies_the_guard() {
    let migrations = vec![
        crate::migration::Migration::<fn()>::new(1, "m").sql("CREATE TABLE a (x INT); COMMIT")
    ];
    assert!(matches!(
        crate::migration::validate_registry(&migrations),
        Err(Error::InvalidRegistry(_))
    ));
}
