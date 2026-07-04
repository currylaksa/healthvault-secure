-- Argon2id migration for staff_credentials (replaces legacy MD5).
USE `medic_vault_db`;
UPDATE `staff_credentials` SET `auth_key_hash` = '$argon2id$v=19$m=65536,t=4,p=2$bXVsellSelVkM0hNaUJFUQ$xka9bn3UWoh1NIfSofzJSfGxA8mfgLKrto7BTFX37CE' WHERE `username` = 'dr_faizal';
UPDATE `staff_credentials` SET `auth_key_hash` = '$argon2id$v=19$m=65536,t=4,p=2$bElJV1pINGFITE9yVEdLZA$vNYqeQga0V58JZUk5tinmhIcwRNz0V9gR3IQpEUvUA0' WHERE `username` = 'dr_sharifah';
