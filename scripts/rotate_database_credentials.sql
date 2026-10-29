-- SR10: run against the existing database as an administrative user after setting
-- @application_username and @new_application_password in the interactive client.
-- This script intentionally contains no usable credential.

DELIMITER //
CREATE PROCEDURE rotate_application_credential()
BEGIN
  IF @application_username IS NULL OR @application_username = ''
     OR @new_application_password IS NULL OR CHAR_LENGTH(@new_application_password) < 20 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Set the application username and a generated password of at least 20 characters';
  END IF;
  SET @alter_statement = CONCAT(
    "ALTER USER '", REPLACE(@application_username, "'", "''"), "'@'%' IDENTIFIED BY '",
    REPLACE(@new_application_password, "'", "''"), "'"
  );
  PREPARE credential_rotation FROM @alter_statement;
  EXECUTE credential_rotation;
  DEALLOCATE PREPARE credential_rotation;
END//
DELIMITER ;

CALL rotate_application_credential();
DROP PROCEDURE rotate_application_credential;
