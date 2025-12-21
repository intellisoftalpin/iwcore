//! Database schema definitions

/// SQL to create the properties table
pub const CREATE_PROPERTIES_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS nswallet_properties (
    database_id     CHAR(32) NOT NULL PRIMARY KEY,
    lang            CHAR(2),
    version         CHAR(10),
    email           CHAR(200),
    sync_timestamp  TEXT,
    update_timestamp TEXT
)
"#;

/// SQL to create the items table
pub const CREATE_ITEMS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS nswallet_items (
    item_id         CHAR(8) NOT NULL PRIMARY KEY,
    parent_id       CHAR(8),
    name            BLOB,
    icon            CHAR(48),
    field_id        CHAR(4),
    folder          INTEGER,
    create_timestamp TEXT,
    change_timestamp TEXT,
    deleted         INTEGER DEFAULT 0
)
"#;

/// SQL to create the fields table (composite primary key)
pub const CREATE_FIELDS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS nswallet_fields (
    item_id         CHAR(8) NOT NULL,
    field_id        CHAR(4) NOT NULL,
    type            CHAR(4),
    value           BLOB,
    change_timestamp TEXT,
    deleted         INTEGER DEFAULT 0,
    sort_weight     INTEGER,
    PRIMARY KEY (item_id, field_id)
)
"#;

/// SQL to create the labels table
pub const CREATE_LABELS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS nswallet_labels (
    field_type      VARCHAR PRIMARY KEY NOT NULL,
    label_name      VARCHAR,
    value_type      VARCHAR,
    icon            VARCHAR,
    system          INTEGER,
    change_timestamp TEXT,
    deleted         INTEGER DEFAULT 0
)
"#;

/// SQL to create the icons table (without blob - only metadata)
pub const CREATE_ICONS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS nswallet_icons (
    icon_id         VARCHAR PRIMARY KEY NOT NULL,
    name            VARCHAR,
    icon_blob       BLOB,
    group_id        INTEGER,
    is_circle       INTEGER DEFAULT 1,
    deleted         INTEGER DEFAULT 0
)
"#;

/// SQL to create the groups table
pub const CREATE_GROUPS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS nswallet_groups (
    group_id        INTEGER PRIMARY KEY NOT NULL,
    name            VARCHAR,
    deleted         INTEGER DEFAULT 0
)
"#;

/// SQL to create the labels view with usage count
pub const CREATE_LABELS_VIEW: &str = r#"
CREATE VIEW IF NOT EXISTS nswallet_labels_view AS
SELECT
    nswallet_labels.field_type,
    nswallet_labels.label_name,
    nswallet_labels.value_type,
    nswallet_labels.icon,
    nswallet_labels.system,
    nswallet_labels.change_timestamp,
    nswallet_labels.deleted,
    COUNT(nswallet_fields.type) as usage
FROM nswallet_labels
LEFT JOIN nswallet_fields
    ON nswallet_labels.field_type = nswallet_fields.type
WHERE nswallet_labels.deleted = 0
GROUP BY nswallet_labels.field_type
ORDER BY usage DESC
"#;

/// All table creation statements in order
pub const CREATE_ALL_TABLES: &[&str] = &[
    CREATE_PROPERTIES_TABLE,
    CREATE_ITEMS_TABLE,
    CREATE_FIELDS_TABLE,
    CREATE_LABELS_TABLE,
    CREATE_ICONS_TABLE,
    CREATE_GROUPS_TABLE,
];
