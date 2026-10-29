-- SR10: run as a database administrator after setting @application_username.
-- The runtime application performs CRUD only; schema setup and migrations use
-- an administrative account and are intentionally excluded from this grant.

USE mysql;

DELIMITER //
CREATE PROCEDURE restrict_application_privileges()
BEGIN
  IF @application_username IS NULL OR @application_username = '' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Set the application username';
  END IF;

  SET @quoted_user = REPLACE(@application_username, "'", "''");
  SET @revoke_sql = CONCAT(
    "REVOKE ALL PRIVILEGES, GRANT OPTION FROM '", @quoted_user, "'@'%'"
  );
  PREPARE revoke_statement FROM @revoke_sql;
  EXECUTE revoke_statement;
  DEALLOCATE PREPARE revoke_statement;

  SET @grant_sql = CONCAT(
    "GRANT SELECT, INSERT, UPDATE, DELETE ON airport_security.* TO '",
    @quoted_user,
    "'@'%'"
  );
  PREPARE grant_statement FROM @grant_sql;
  EXECUTE grant_statement;
  DEALLOCATE PREPARE grant_statement;
END//
DELIMITER ;

CALL restrict_application_privileges();
DROP PROCEDURE restrict_application_privileges;
