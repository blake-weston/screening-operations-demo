<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$adminUser = require_admin();
$allowedRoles = ['lane', 'manager', 'admin'];
$allowedTerminals = ['Terminal 2'];
$allowedLaneNumbers = [1, 2, 3, 4];
$errors = [];
$editingOperatorId = (int) ($_GET['edit'] ?? 0);

function operator_snapshot(int $operatorId): ?array
{
    $statement = db()->prepare(
        'SELECT id, username, display_name, role, is_active
         FROM operators
         WHERE id = :id
         LIMIT 1'
    );
    $statement->execute(['id' => $operatorId]);
    $operator = $statement->fetch();

    if (!$operator) {
        return null;
    }

    $assignmentStatement = db()->prepare(
        'SELECT terminal_name, lane_number
         FROM operator_lane_assignments
         WHERE operator_id = :operator_id
         ORDER BY terminal_name, lane_number'
    );
    $assignmentStatement->execute(['operator_id' => $operatorId]);
    $operator['lane_assignments'] = $assignmentStatement->fetchAll();

    return $operator;
}

function format_lane_assignment_summary(array $assignments): string
{
    if ($assignments === []) {
        return 'All lanes';
    }

    $parts = [];
    foreach ($assignments as $assignment) {
        $parts[] = $assignment['terminal_name'] . ' Lane ' . $assignment['lane_number'];
    }

    return implode(', ', $parts);
}

function audit_operator_action(int $actorOperatorId, ?int $targetOperatorId, string $action, array $details, string $ipAddress): void
{
    $statement = db()->prepare(
        'INSERT INTO operator_audit_logs (actor_operator_id, target_operator_id, action, details, ip_address)
         VALUES (:actor_operator_id, :target_operator_id, :action, :details, :ip_address)'
    );
    $statement->execute([
        'actor_operator_id' => $actorOperatorId,
        'target_operator_id' => $targetOperatorId,
        'action' => $action,
        'details' => json_encode($details, JSON_THROW_ON_ERROR),
        'ip_address' => $ipAddress,
    ]);
}

function parse_lane_numbers(array $rawLaneNumbers, array $allowedLaneNumbers): array
{
    $laneNumbers = [];

    foreach ($rawLaneNumbers as $part) {
        $value = trim((string) $part);
        if ($value === '' || !ctype_digit($value)) {
            return [];
        }

        $lane = (int) $value;
        if (!in_array($lane, $allowedLaneNumbers, true)) {
            return [];
        }

        $laneNumbers[] = $lane;
    }

    $laneNumbers = array_values(array_unique($laneNumbers));
    sort($laneNumbers);

    return $laneNumbers;
}

function replace_lane_assignments(int $operatorId, string $role, string $terminalName, array $laneNumbers): void
{
    $deleteStatement = db()->prepare('DELETE FROM operator_lane_assignments WHERE operator_id = :operator_id');
    $deleteStatement->execute(['operator_id' => $operatorId]);

    if ($role !== 'lane') {
        return;
    }

    $insertStatement = db()->prepare(
        'INSERT INTO operator_lane_assignments (operator_id, terminal_name, lane_number)
         VALUES (:operator_id, :terminal_name, :lane_number)'
    );

    foreach ($laneNumbers as $laneNumber) {
        $insertStatement->execute([
            'operator_id' => $operatorId,
            'terminal_name' => $terminalName,
            'lane_number' => $laneNumber,
        ]);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? null)) {
        $errors[] = 'The request could not be verified. Refresh the page and try again.';
    } else {
        $action = (string) ($_POST['action'] ?? '');
        $ipAddress = client_ip_address();

        if ($action === 'update') {
            $operatorId = (int) ($_POST['operator_id'] ?? 0);
            $displayName = trim((string) ($_POST['display_name'] ?? ''));
            $role = trim((string) ($_POST['role'] ?? ''));
            $isActive = isset($_POST['is_active']) ? 1 : 0;
            $password = (string) ($_POST['password'] ?? '');
            $terminalName = trim((string) ($_POST['terminal_name'] ?? ''));
            $laneNumbers = parse_lane_numbers((array) ($_POST['lane_numbers'] ?? []), $allowedLaneNumbers);
            $existingOperator = $operatorId > 0 ? operator_snapshot($operatorId) : null;

            if ($operatorId <= 0) {
                $errors[] = 'Invalid operator selected.';
            }

            if ($operatorId > 0 && $existingOperator === null) {
                $errors[] = 'The selected operator could not be found.';
            }

            if ($displayName === '' || strlen($displayName) > 100) {
                $errors[] = 'Display name must be between 1 and 100 characters.';
            }

            if (!in_array($role, $allowedRoles, true)) {
                $errors[] = 'Invalid role selected.';
            }

            if ($operatorId === (int) $adminUser['id'] && $role !== 'admin') {
                $errors[] = 'You cannot remove administrator access from the current signed-in account.';
            }

            if ($password !== '' && strlen($password) < 12) {
                $errors[] = 'Updated passwords must be at least 12 characters.';
            }

            if ($role === 'lane') {
                if (!in_array($terminalName, $allowedTerminals, true)) {
                    $errors[] = 'Lane operators require a valid terminal selection.';
                }

                if ($laneNumbers === []) {
                    $errors[] = 'Lane operators must be assigned one or more comma-separated lane numbers.';
                }
            }

            if ($errors === []) {
                db()->beginTransaction();

                try {
                    $beforeState = operator_snapshot($operatorId);
                    if ($beforeState === null) {
                        throw new RuntimeException('The selected operator could not be found.');
                    }

                    if ($password === '') {
                        $statement = db()->prepare(
                            'UPDATE operators
                             SET display_name = :display_name,
                                 role = :role,
                                 is_active = :is_active
                             WHERE id = :id'
                        );
                        $statement->execute([
                            'id' => $operatorId,
                            'display_name' => $displayName,
                            'role' => $role,
                            'is_active' => $isActive,
                        ]);
                    } else {
                        $statement = db()->prepare(
                            'UPDATE operators
                             SET display_name = :display_name,
                                 role = :role,
                                 is_active = :is_active,
                                 password_hash = :password_hash
                             WHERE id = :id'
                        );
                        $statement->execute([
                            'id' => $operatorId,
                            'display_name' => $displayName,
                            'role' => $role,
                            'is_active' => $isActive,
                            'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                        ]);
                    }

                    replace_lane_assignments($operatorId, $role, $terminalName, $laneNumbers);
                    $afterState = operator_snapshot($operatorId);
                    if ($afterState === null) {
                        throw new RuntimeException('The updated operator could not be loaded.');
                    }

                    audit_operator_action(
                        (int) $adminUser['id'],
                        $operatorId,
                        'operator_updated',
                        [
                            'target_username' => $afterState['username'],
                            'password_reset' => $password !== '',
                            'before' => [
                                'display_name' => $beforeState['display_name'],
                                'role' => $beforeState['role'],
                                'is_active' => (bool) $beforeState['is_active'],
                                'lane_assignments' => format_lane_assignment_summary($beforeState['lane_assignments']),
                            ],
                            'after' => [
                                'display_name' => $afterState['display_name'],
                                'role' => $afterState['role'],
                                'is_active' => (bool) $afterState['is_active'],
                                'lane_assignments' => format_lane_assignment_summary($afterState['lane_assignments']),
                            ],
                        ],
                        $ipAddress
                    );
                    db()->commit();
                } catch (Throwable $throwable) {
                    db()->rollBack();
                    throw $throwable;
                }

                flash('success', 'Operator account updated.');
                redirect('/operators.php');
            }
        } elseif ($action === 'create') {
            $username = trim((string) ($_POST['username'] ?? ''));
            $displayName = trim((string) ($_POST['display_name'] ?? ''));
            $role = trim((string) ($_POST['role'] ?? ''));
            $password = (string) ($_POST['password'] ?? '');
            $terminalName = trim((string) ($_POST['terminal_name'] ?? ''));
            $laneNumbers = parse_lane_numbers((array) ($_POST['lane_numbers'] ?? []), $allowedLaneNumbers);

            if ($username === '' || strlen($username) < 3 || strlen($username) > 50 || !preg_match('/^[A-Za-z0-9._-]+$/', $username)) {
                $errors[] = 'Username must be 3 to 50 characters and use letters, numbers, dots, underscores, or hyphens.';
            }

            if ($displayName === '' || strlen($displayName) > 100) {
                $errors[] = 'Display name must be between 1 and 100 characters.';
            }

            if (!in_array($role, $allowedRoles, true)) {
                $errors[] = 'Invalid role selected.';
            }

            if (strlen($password) < 12) {
                $errors[] = 'Passwords must be at least 12 characters.';
            }

            if ($role === 'lane') {
                if (!in_array($terminalName, $allowedTerminals, true)) {
                    $errors[] = 'Lane operators require a valid terminal selection.';
                }

                if ($laneNumbers === []) {
                    $errors[] = 'Lane operators must be assigned one or more comma-separated lane numbers.';
                }
            }

            if ($errors === []) {
                try {
                    db()->beginTransaction();
                    $statement = db()->prepare(
                        'INSERT INTO operators (username, display_name, password_hash, role, is_active)
                         VALUES (:username, :display_name, :password_hash, :role, 1)'
                    );
                    $statement->execute([
                        'username' => $username,
                        'display_name' => $displayName,
                        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                        'role' => $role,
                    ]);

                    $operatorId = (int) db()->lastInsertId();
                    replace_lane_assignments($operatorId, $role, $terminalName, $laneNumbers);
                    $createdOperator = operator_snapshot($operatorId);
                    if ($createdOperator === null) {
                        throw new RuntimeException('The created operator could not be loaded.');
                    }

                    audit_operator_action(
                        (int) $adminUser['id'],
                        $operatorId,
                        'operator_created',
                        [
                            'target_username' => $createdOperator['username'],
                            'display_name' => $createdOperator['display_name'],
                            'role' => $createdOperator['role'],
                            'is_active' => (bool) $createdOperator['is_active'],
                            'lane_assignments' => format_lane_assignment_summary($createdOperator['lane_assignments']),
                        ],
                        $ipAddress
                    );
                    db()->commit();

                    flash('success', 'Operator account created.');
                    redirect('/operators.php');
                } catch (Throwable $exception) {
                    if (db()->inTransaction()) {
                        db()->rollBack();
                    }
                    if ($exception instanceof PDOException && $exception->getCode() === '23000') {
                        $errors[] = 'That username already exists.';
                    } else {
                        $errors[] = 'The operator account could not be created right now.';
                    }
                }
            }
        } else {
            $errors[] = 'Unsupported action.';
        }
    }
}

$auditLogEntries = db()->query(
    'SELECT
        oal.id,
        oal.action,
        oal.details,
        oal.ip_address,
        oal.occurred_at,
        actor.username AS actor_username,
        target.username AS target_username
     FROM operator_audit_logs oal
     INNER JOIN operators actor ON actor.id = oal.actor_operator_id
     LEFT JOIN operators target ON target.id = oal.target_operator_id
     ORDER BY oal.occurred_at DESC, oal.id DESC
     LIMIT 20'
)->fetchAll();

$operators = db()->query(
    'SELECT
        o.id,
        o.username,
        o.display_name,
        o.role,
        o.is_active,
        o.created_at,
        GROUP_CONCAT(CONCAT(ola.terminal_name, " Lane ", ola.lane_number) ORDER BY ola.terminal_name, ola.lane_number SEPARATOR ", ") AS lane_assignments,
        MIN(ola.terminal_name) AS primary_terminal,
        GROUP_CONCAT(ola.lane_number ORDER BY ola.lane_number SEPARATOR ",") AS lane_numbers
     FROM operators o
     LEFT JOIN operator_lane_assignments ola ON ola.operator_id = o.id
     GROUP BY o.id, o.username, o.display_name, o.role, o.is_active, o.created_at
     ORDER BY o.id ASC'
)->fetchAll();

render_header('Security Administrator');
?>
<main class="card">
  <h1>Security Administrator</h1>
  <?php if ($errors !== []): ?>
    <div class="flash flash-error"><?= escape_html(implode(' ', $errors)) ?></div>
  <?php endif; ?>
</main>

<section class="card card-spaced">
  <h2>Existing operators</h2>
  <table>
    <thead>
      <tr>
        <th>Username</th>
        <th>Display name</th>
        <th>Role</th>
        <th>Assignments</th>
        <th>Active</th>
        <th>Created</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      <?php foreach ($operators as $operator): ?>
        <?php $selectedLaneNumbers = ($operator['lane_numbers'] ?? '') === '' ? [] : explode(',', (string) $operator['lane_numbers']); ?>
        <?php if ($editingOperatorId === (int) $operator['id']): ?>
          <tr>
            <form method="post" action="/operators.php">
              <td>
                <?= escape_html($operator['username']) ?>
                <input type="hidden" name="csrf_token" value="<?= escape_html(csrf_token()) ?>">
                <input type="hidden" name="action" value="update">
                <input type="hidden" name="operator_id" value="<?= escape_html((string) $operator['id']) ?>">
              </td>
              <td>
                <input
                  type="text"
                  name="display_name"
                  maxlength="100"
                  value="<?= escape_html($operator['display_name']) ?>"
                >
              </td>
              <td>
                <select name="role">
                  <?php foreach ($allowedRoles as $allowedRole): ?>
                    <option value="<?= escape_html($allowedRole) ?>"<?= $operator['role'] === $allowedRole ? ' selected' : '' ?>>
                      <?= escape_html($allowedRole) ?>
                    </option>
                  <?php endforeach; ?>
                </select>
              </td>
              <td>
                <label for="terminal-<?= escape_html((string) $operator['id']) ?>">Terminal</label>
                <select id="terminal-<?= escape_html((string) $operator['id']) ?>" name="terminal_name">
                  <option value="">No terminal assignment</option>
                  <?php foreach ($allowedTerminals as $allowedTerminal): ?>
                    <option value="<?= escape_html($allowedTerminal) ?>"<?= ($operator['primary_terminal'] ?? '') === $allowedTerminal ? ' selected' : '' ?>>
                      <?= escape_html($allowedTerminal) ?>
                    </option>
                  <?php endforeach; ?>
                </select>
                <label for="lanes-<?= escape_html((string) $operator['id']) ?>">Lanes</label>
                <div id="lanes-<?= escape_html((string) $operator['id']) ?>">
                  <?php foreach ($allowedLaneNumbers as $allowedLaneNumber): ?>
                    <label class="choice-label">
                      <input
                        type="checkbox"
                        name="lane_numbers[]"
                        value="<?= escape_html((string) $allowedLaneNumber) ?>"
                        class="choice-input"
                        <?= in_array((string) $allowedLaneNumber, $selectedLaneNumbers, true) ? 'checked' : '' ?>
                      >
                      Lane <?= escape_html((string) $allowedLaneNumber) ?>
                    </label>
                  <?php endforeach; ?>
                </div>
              </td>
              <td>
                <label class="choice-label choice-label-last">
                  <input
                    type="checkbox"
                    name="is_active"
                    value="1"
                    class="choice-input"
                    <?= (int) $operator['is_active'] === 1 ? 'checked' : '' ?>
                  >
                </label>
              </td>
              <td><?= escape_html($operator['created_at']) ?></td>
              <td>
                <label for="password-<?= escape_html((string) $operator['id']) ?>">New password</label>
                <input
                  id="password-<?= escape_html((string) $operator['id']) ?>"
                  type="password"
                  name="password"
                  placeholder="Leave blank to keep current"
                >
                <div class="actions">
                  <button type="submit">Save</button>
                  <a class="button button-secondary" href="/operators.php">Cancel</a>
                </div>
              </td>
            </form>
          </tr>
        <?php else: ?>
          <tr>
            <td><?= escape_html($operator['username']) ?></td>
            <td><?= escape_html($operator['display_name']) ?></td>
            <td><?= escape_html($operator['role']) ?></td>
            <td><?= escape_html((string) ($operator['lane_assignments'] ?? 'All lanes')) ?></td>
            <td><?= (int) $operator['is_active'] === 1 ? '&#10003;' : '&#10007;' ?></td>
            <td><?= escape_html($operator['created_at']) ?></td>
            <td>
              <a class="button button-secondary" href="/operators.php?edit=<?= escape_html((string) $operator['id']) ?>">Edit</a>
            </td>
          </tr>
        <?php endif; ?>
      <?php endforeach; ?>
    </tbody>
  </table>
</section>

<section class="card card-spaced">
  <h2>Create operator</h2>
  <form method="post" action="/operators.php" novalidate>
    <input type="hidden" name="csrf_token" value="<?= escape_html(csrf_token()) ?>">
    <input type="hidden" name="action" value="create">

    <label for="username">Username</label>
    <input id="username" name="username" type="text" maxlength="50" required>

    <label for="display_name">Display name</label>
    <input id="display_name" name="display_name" type="text" maxlength="100" required>

    <label for="role">Role</label>
    <select id="role" name="role">
      <?php foreach ($allowedRoles as $allowedRole): ?>
        <option value="<?= escape_html($allowedRole) ?>"><?= escape_html($allowedRole) ?></option>
      <?php endforeach; ?>
    </select>

    <label for="password">Password</label>
    <input id="password" name="password" type="password" minlength="12" required>

    <label for="terminal_name">Terminal</label>
    <select id="terminal_name" name="terminal_name">
      <option value="">Select terminal</option>
      <?php foreach ($allowedTerminals as $allowedTerminal): ?>
        <option value="<?= escape_html($allowedTerminal) ?>"><?= escape_html($allowedTerminal) ?></option>
      <?php endforeach; ?>
    </select>

    <label for="lane_numbers">Lane numbers</label>
    <div id="lane_numbers">
      <?php foreach ($allowedLaneNumbers as $allowedLaneNumber): ?>
        <label class="choice-label">
          <input
            type="checkbox"
            name="lane_numbers[]"
            value="<?= escape_html((string) $allowedLaneNumber) ?>"
            class="choice-input"
          >
          Lane <?= escape_html((string) $allowedLaneNumber) ?>
        </label>
      <?php endforeach; ?>
    </div>

    <button type="submit">Create operator</button>
  </form>
</section>

<section class="card card-spaced">
  <h2>Administrative audit log</h2>
  <table>
    <thead>
      <tr>
        <th>Time</th>
        <th>Administrator</th>
        <th>Action</th>
        <th>Target</th>
        <th>Source IP</th>
        <th>Details</th>
      </tr>
    </thead>
    <tbody>
      <?php foreach ($auditLogEntries as $entry): ?>
        <?php $details = json_decode((string) $entry['details'], true) ?: []; ?>
        <tr>
          <td><?= escape_html((string) $entry['occurred_at']) ?></td>
          <td><?= escape_html((string) $entry['actor_username']) ?></td>
          <td><?= escape_html(str_replace('_', ' ', (string) $entry['action'])) ?></td>
          <td><?= escape_html((string) ($entry['target_username'] ?? ($details['target_username'] ?? 'Unknown'))) ?></td>
          <td><?= escape_html((string) $entry['ip_address']) ?></td>
          <td><pre class="audit-details"><?= escape_html(json_encode($details, JSON_PRETTY_PRINT) ?: '{}') ?></pre></td>
        </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</section>
<?php
render_footer();
