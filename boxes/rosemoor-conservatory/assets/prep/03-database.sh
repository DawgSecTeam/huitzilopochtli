#!/bin/sh
# Rosemoor prep 03/05 -- the collections database: schema, seed rows, the
# app's service account, and a general query log (which makes the database
# itself an IR source on this box). The nakon plants layer their insecure
# account/bind settings on top of this afterwards.
set -eu

mysql <<'SQL'
CREATE DATABASE IF NOT EXISTS glassboard;
USE glassboard;
CREATE TABLE IF NOT EXISTS collections (
  id INT PRIMARY KEY,
  species VARCHAR(160),
  latin_name VARCHAR(160),
  house VARCHAR(60),
  rarity VARCHAR(40),
  accession_no VARCHAR(32)
);
CREATE TABLE IF NOT EXISTS tickets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  visit_date DATE,
  visitor_type VARCHAR(40),
  quantity INT
);
CREATE TABLE IF NOT EXISTS sensors (
  id INT AUTO_INCREMENT PRIMARY KEY,
  house VARCHAR(60),
  metric VARCHAR(40),
  reading DECIMAL(6,2),
  recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO collections (id, species, latin_name, house, rarity, accession_no) VALUES
  (1,'Ghost Orchid','Dendrophylax lindenii','Tropical High House','RARE','RO-2026-001'),
  (2,'Corpse Flower','Amorphophallus titanum','Tropical High House','RARE','RO-2026-002'),
  (3,'Lady Slipper','Cypripedium reginae','Temperate House','UNCOMMON','RO-2026-003'),
  (4,'Black Bat Flower','Tacca chantrieri','Tropical Low House','UNCOMMON','RO-2026-004'),
  (5,'Jade Vine','Strongylodon macrobotrys','Tropical Low House','RARE','RO-2026-005'),
  (6,'Blue Poppy','Meconopsis grandis','Alpine House','UNCOMMON','RO-2026-006'),
  (7,'Edelweiss','Leontopodium nivale','Alpine House','COMMON','RO-2026-007'),
  (8,'Venus Flytrap','Dionaea muscipula','Carnivore Bench','COMMON','RO-2026-008');
INSERT INTO tickets (visit_date, visitor_type, quantity) VALUES
  (CURDATE(),'adult',42),(CURDATE(),'child',31),(CURDATE(),'member',12);
INSERT INTO sensors (house, metric, reading) VALUES
  ('Tropical High House','tempC',28.4),('Tropical High House','humidity',81),
  ('Tropical Low House','tempC',24.1),('Tropical Low House','humidity',76),
  ('Alpine House','tempC',12.9),('Alpine House','humidity',58);

CREATE USER IF NOT EXISTS 'glassapp'@'localhost' IDENTIFIED BY 'GlassDB-2026!';
GRANT ALL PRIVILEGES ON glassboard.* TO 'glassapp'@'localhost';
FLUSH PRIVILEGES;
SQL

# -- general query log on (to the file IR reads) ------------------------------
mkdir -p /var/log/mysql
chown mysql:mysql /var/log/mysql
mysql -e "SET GLOBAL general_log_file='/var/log/mysql/general.log';
          SET GLOBAL general_log=1;"

echo "prep03: glassboard database ready; glassapp account provisioned; query log on"
