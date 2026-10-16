-- Phishing Detection System schema (MySQL 8+)
CREATE DATABASE IF NOT EXISTS phishing_detection
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE phishing_detection;

CREATE TABLE IF NOT EXISTS scan_history (
  id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scanned_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  normalized_url       VARCHAR(2048) NOT NULL,
  url_hash             CHAR(64) NOT NULL,           -- SHA-256 of normalized_url (indexable)
  host                 VARCHAR(253) NOT NULL,
  prediction           ENUM('safe','suspicious','phishing') NOT NULL,
  phishing_probability DECIMAL(5,4) NOT NULL,       -- 0.0000 - 1.0000
  model_name           VARCHAR(64) NOT NULL,
  features             JSON NOT NULL,               -- extracted feature values
  PRIMARY KEY (id),
  KEY idx_scanned_at (scanned_at),
  KEY idx_prediction (prediction),
  KEY idx_url_hash (url_hash),
  KEY idx_host (host)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS model_metrics (
  id                  INT UNSIGNED NOT NULL AUTO_INCREMENT,
  trained_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  model_name          VARCHAR(64) NOT NULL,
  dataset_name        VARCHAR(128) NOT NULL,
  n_train             INT UNSIGNED NOT NULL,
  n_test              INT UNSIGNED NOT NULL,
  accuracy            DECIMAL(6,5) NOT NULL,
  precision_score     DECIMAL(6,5) NOT NULL,
  recall_score        DECIMAL(6,5) NOT NULL,
  f1_score            DECIMAL(6,5) NOT NULL,
  roc_auc             DECIMAL(6,5) NULL,
  false_positive_rate DECIMAL(6,5) NOT NULL,
  tn INT UNSIGNED NOT NULL, fp INT UNSIGNED NOT NULL,
  fn INT UNSIGNED NOT NULL, tp INT UNSIGNED NOT NULL,
  is_selected         TINYINT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  KEY idx_model_name (model_name),
  KEY idx_is_selected (is_selected)
) ENGINE=InnoDB;

-- Least-privilege app user (run in a MySQL shell with your own password; never commit it):
-- CREATE USER 'phishing_app'@'localhost' IDENTIFIED BY 'your-strong-password';
-- GRANT SELECT, INSERT ON phishing_detection.scan_history TO 'phishing_app'@'localhost';
-- GRANT SELECT, INSERT, UPDATE ON phishing_detection.model_metrics TO 'phishing_app'@'localhost';
