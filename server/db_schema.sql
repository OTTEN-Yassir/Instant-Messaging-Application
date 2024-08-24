BEGIN TRANSACTION;
DROP TABLE IF EXISTS "groups";
CREATE TABLE IF NOT EXISTS "groups" (
	"id"	INTEGER,
	"name"	TEXT NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);
DROP TABLE IF EXISTS "group_users";
CREATE TABLE IF NOT EXISTS "group_users" (
	"group"	INTEGER,
	"user"	TEXT,
	FOREIGN KEY("group") REFERENCES "groups"("id"),
	PRIMARY KEY("group","user"),
	FOREIGN KEY("user") REFERENCES "users"("username")
);
DROP TABLE IF EXISTS "users";
CREATE TABLE IF NOT EXISTS "users" (
	"username"	TEXT NOT NULL,
	"password"	TEXT NOT NULL,
	PRIMARY KEY("username")
);
DROP TABLE IF EXISTS "public_keys";
CREATE TABLE IF NOT EXISTS "public_keys" (
	"id"	TEXT NOT NULL,
	"owner"	TEXT NOT NULL,
	"key"	TEXT NOT NULL,
	PRIMARY KEY("id"),
	FOREIGN KEY("owner") REFERENCES "users"("username")
);
DROP TABLE IF EXISTS "contacts";
CREATE TABLE IF NOT EXISTS "contacts" (
	"user"	TEXT NOT NULL,
	"contact"	TEXT NOT NULL,
	FOREIGN KEY("user") REFERENCES "users"("username"),
	FOREIGN KEY("contact") REFERENCES "users"("username"),
	PRIMARY KEY("user","contact")
);
DROP TABLE IF EXISTS "group_messages";
CREATE TABLE IF NOT EXISTS "group_messages" (
	"id"	INTEGER NOT NULL,
	"to"	INTEGER NOT NULL,
	PRIMARY KEY("id"),
	FOREIGN KEY("id") REFERENCES "messages"("id"),
	FOREIGN KEY("to") REFERENCES "groups"("id")
);
DROP TABLE IF EXISTS "direct_messages";
CREATE TABLE IF NOT EXISTS "direct_messages" (
	"id"	INTEGER NOT NULL,
	"to"	TEXT NOT NULL,
	FOREIGN KEY("id") REFERENCES "messages"("id"),
	PRIMARY KEY("id"),
	FOREIGN KEY("to") REFERENCES "users"("username")
);
DROP TABLE IF EXISTS "messages";
CREATE TABLE IF NOT EXISTS "messages" (
	"id"	INTEGER,
	"from"	TEXT NOT NULL,
	"timestamp"	INTEGER NOT NULL,
	"content"	TEXT NOT NULL COLLATE BINARY,
	"decryption_key"	TEXT NOT NULL COLLATE BINARY,
	FOREIGN KEY("from") REFERENCES "users"("username"),
	PRIMARY KEY("id" AUTOINCREMENT)
);
DROP TABLE IF EXISTS "group_files";
CREATE TABLE IF NOT EXISTS "group_files" (
	"id"	INTEGER NOT NULL,
	"to"	INTEGER NOT NULL,
	FOREIGN KEY("to") REFERENCES "groups"("id"),
	PRIMARY KEY("id"),
	FOREIGN KEY("id") REFERENCES "files"("id")
);
DROP TABLE IF EXISTS "direct_files";
CREATE TABLE IF NOT EXISTS "direct_files" (
	"id"	INTEGER NOT NULL,
	"to"	TEXT NOT NULL,
	FOREIGN KEY("id") REFERENCES "files"("id"),
	FOREIGN KEY("to") REFERENCES "users"("username"),
	PRIMARY KEY("id")
);
DROP TABLE IF EXISTS "files";
CREATE TABLE IF NOT EXISTS "files" (
	"id"	INTEGER,
	"localname"	TEXT NOT NULL,
	"filename"	TEXT NOT NULL,
	"from"	TEXT NOT NULL,
	"timestamp"	INTEGER NOT NULL,
	"decryption_key"	TEXT NOT NULL,
	FOREIGN KEY("from") REFERENCES "users"("username"),
	PRIMARY KEY("id" AUTOINCREMENT)
);
COMMIT;
