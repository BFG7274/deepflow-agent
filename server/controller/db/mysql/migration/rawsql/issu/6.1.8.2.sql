ALTER TABLE vinterface ADD COLUMN updated_at DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

UPDATE db_version SET version = '6.1.8.2';
