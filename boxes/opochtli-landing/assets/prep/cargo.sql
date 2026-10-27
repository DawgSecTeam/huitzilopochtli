-- Shared port-authority database for the cargo-manifest lookup app.
--
-- Run this ONCE as root on the database host -- never on a scored practice
-- box. It creates the `portauthority` database, the SELECT-only
-- `portauthority` account, and the themed manifest rows the app reads.
--
-- PLACEHOLDERS: `192.0.2.%` is an RFC 5737 documentation address standing in
-- for the practice-network subnet the app connects from, and `change-me` for
-- the account password. Substitute both at deploy time and keep them in step
-- with the app's connection settings (see prep-notes.md) and with the egress
-- rule the scenario scores. The database host listens on 3306 and must accept
-- connections from that subnet.
CREATE DATABASE IF NOT EXISTS portauthority;
CREATE USER IF NOT EXISTS 'portauthority'@'192.0.2.%' IDENTIFIED BY 'change-me';
GRANT SELECT ON portauthority.* TO 'portauthority'@'192.0.2.%';
USE portauthority;
CREATE TABLE IF NOT EXISTS cargo_manifest (
  id INT AUTO_INCREMENT PRIMARY KEY,
  vessel VARCHAR(64) NOT NULL,
  berth VARCHAR(8) NOT NULL,
  cargo VARCHAR(128) NOT NULL,
  consignee VARCHAR(96) NOT NULL,
  status VARCHAR(24) NOT NULL
);
DELETE FROM cargo_manifest;
INSERT INTO cargo_manifest (vessel, berth, cargo, consignee, status) VALUES
('MV Coyolxauhqui','7','cocoa concentrate, 40 containers','Cocoa Falls Chocolate Works','cleared'),
('MV Ridge Runner','9','telescope optics, fragile','Coyolxauhqui Ridge Solar Observatory','cleared'),
('MV Halcyon Tide','12','mixed general cargo','various','offloading'),
('MV Cinnamon Dawn','3','bulk grain','Opochtli Landing Grain Co-op','customs hold'),
('MV Kestrel Bay','15','refrigerated seafood','Landing Fishmarket','cleared'),
('MV Saltbranch','18','timber and pitch','Harbor Works Yard','expected');
FLUSH PRIVILEGES;
