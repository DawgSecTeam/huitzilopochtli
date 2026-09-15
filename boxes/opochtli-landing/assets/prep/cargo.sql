-- Shared port-authority database (workshop-shared-mariadb, 192.168.100.10).
-- User is SELECT-only and reachable only from the workshop guest network.
CREATE DATABASE IF NOT EXISTS portauthority;
CREATE USER IF NOT EXISTS 'portauthority'@'192.168.100.%' IDENTIFIED BY 'manifest-db';
GRANT SELECT ON portauthority.* TO 'portauthority'@'192.168.100.%';
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
