-- Lantern Hill Community Library -- catalog schema + seed data.
-- Run ON the box by prep (04-database.sh): creates the `library` database,
-- the app's least-privilege account, and enough rows to look lived in.

CREATE DATABASE IF NOT EXISTS library CHARACTER SET utf8mb4;
USE library;

CREATE TABLE IF NOT EXISTS books (
  id INT PRIMARY KEY,
  title VARCHAR(160) NOT NULL,
  author VARCHAR(120) NOT NULL,
  shelf_code VARCHAR(24) NOT NULL,
  available INT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS patrons (
  id INT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  card_no VARCHAR(24) NOT NULL,
  email VARCHAR(160) NOT NULL
);

CREATE TABLE IF NOT EXISTS holds (
  id INT PRIMARY KEY,
  book_id INT NOT NULL,
  patron_id INT NOT NULL,
  status VARCHAR(24) NOT NULL,
  placed_at DATETIME NOT NULL
);

INSERT INTO books (id, title, author, shelf_code, available) VALUES
  (1, 'Moths of the Northeast', 'R. Alder', '595.78 ALD', 2),
  (2, 'The Lighthouse at Two Lights', 'E. Hopper', '759.13 HOP', 1),
  (3, 'Story Hour: A Memoir', 'M. Carver', 'B CAR', 3),
  (4, 'Bridges of Cedar County', 'L. Okafor', '624.2 OKA', 1),
  (5, 'The Night Shelf', 'A. Wren', 'FIC WRE', 2),
  (6, 'Canning for Beginners', 'P. Solano', '641.4 SOL', 4),
  (7, 'Atlas of Forgotten Trails', 'D. Marsh', '912 MAR', 1),
  (8, 'The Winter Reading Log', 'Lantern Hill Staff', '028.9 LAN', 1);

INSERT INTO patrons (id, name, card_no, email) VALUES
  (1, 'Ruth Ellery',     'LH-2026-0041', 'rellery@example.net'),
  (2, 'Sam Oduya',       'LH-2026-0107', 'soduya@example.net'),
  (3, 'Priya Raman',     'LH-2025-0933', 'praman@example.net'),
  (4, 'Walt Jensen',     'LH-2026-0182', 'wjensen@example.net'),
  (5, 'Iris Fontaine',   'LH-2024-0009', 'ifontaine@example.net'),
  (6, 'Theo Brandvold',  'LH-2026-0220', 'tbrandvold@example.net');

INSERT INTO holds (id, book_id, patron_id, status, placed_at) VALUES
  (1, 5, 1, 'READY',    NOW() - INTERVAL 2 DAY),
  (2, 2, 3, 'PLACED',   NOW() - INTERVAL 1 DAY),
  (3, 1, 6, 'READY',    NOW() - INTERVAL 3 DAY),
  (4, 7, 2, 'PLACED',   NOW() - INTERVAL 5 HOUR),
  (5, 3, 4, 'READY',    NOW() - INTERVAL 26 HOUR),
  (6, 4, 5, 'FULFILLED', NOW() - INTERVAL 9 DAY);

-- The catalog app's least-privilege account (credentials live in
-- /opt/library/.env; keep this grant and that file in agreement).
CREATE USER IF NOT EXISTS 'library_app'@'localhost'
  IDENTIFIED BY 'shelfpass2026';
CREATE USER IF NOT EXISTS 'library_app'@'127.0.0.1'
  IDENTIFIED BY 'shelfpass2026';
GRANT SELECT, UPDATE ON library.*
  TO 'library_app'@'localhost', 'library_app'@'127.0.0.1';
FLUSH PRIVILEGES;
