"""Add versioned routing and records for the department workflow."""
import sqlalchemy as sa
from alembic import op

revision = 'c021_workflow'
down_revision = 'ab2026111101'


def has_column(table, name):
    return not op.get_context().as_sql and any(
        column['name'] == name for column in sa.inspect(op.get_bind()).get_columns(table)
    )


def add_column(table, column):
    if not has_column(table, column.name):
        op.add_column(table, column)


def create_table(table, *columns):
    if op.get_context().as_sql or not sa.inspect(op.get_bind()).has_table(table):
        op.create_table(table, *columns)


def create_index(name, table, columns, **options):
    if op.get_context().as_sql or not any(
        index['name'] == name for index in sa.inspect(op.get_bind()).get_indexes(table)
    ):
        op.create_index(name, table, columns, **options)


def foreign_column(table, name, target):
    if has_column(table, name):
        return
    if op.get_bind().dialect.name == 'sqlite':
        op.execute(f'ALTER TABLE {table} ADD COLUMN {name} INTEGER REFERENCES {target}(id)')
    else:
        op.add_column(table, sa.Column(name, sa.Integer(), sa.ForeignKey(f'{target}.id')))


def foreign(name, target, nullable=True):
    return sa.Column(name, sa.Integer(), sa.ForeignKey(f'{target}.id'), nullable=nullable)


def timestamp(name, nullable=True):
    return sa.Column(name, sa.DateTime(), nullable=nullable)


def upgrade():
    foreign_column('routing_rules', 'category_id', 'categories')
    add_column('routing_rules', sa.Column('version', sa.Integer()))
    for name in ('valid_from', 'valid_to'):
        add_column('routing_rules', timestamp(name))
        add_column('department_members', timestamp(name))
    add_column('department_members', sa.Column('office', sa.Boolean(), nullable=False, server_default=sa.false()))
    create_index('ix_department_office', 'department_members', ['department_id', 'role', 'office', 'valid_to'])
    create_index('ix_category_route_version', 'routing_rules', ['category_id', 'version'], unique=True)
    for name, target in (
        ('category_id', 'categories'), ('route_rule_id', 'routing_rules'),
        ('author_department_id', 'departments'), ('owner_id', 'users'),
    ):
        foreign_column('tickets', name, target)
    add_column('tickets', sa.Column('kind', sa.String(), nullable=False, server_default='REQUEST'))
    add_column('tickets', sa.Column('record_version', sa.Integer(), nullable=False, server_default='1'))
    foreign_column('ticket_status_history', 'actor_id', 'users')
    add_column('ticket_status_history', sa.Column('event_type', sa.String()))
    add_column('ticket_status_history', sa.Column('reason', sa.Text()))
    add_column('ticket_status_history', sa.Column('origin_status', sa.String()))
    add_column('ticket_status_history', sa.Column('author_visible', sa.Boolean(), nullable=False, server_default=sa.false()))
    add_column('ticket_comments', sa.Column('internal', sa.Boolean(), nullable=False, server_default=sa.false()))
    add_column('ticket_attachments', timestamp('created_at'))
    add_column('ticket_attachments', sa.Column('internal', sa.Boolean(), nullable=False, server_default=sa.false()))
    if op.get_context().as_sql or any(
        column['name'] == 'ticket_id' and not column['nullable']
        for column in sa.inspect(op.get_bind()).get_columns('notifications')
    ):
        with op.batch_alter_table('notifications') as batch:
            batch.alter_column('ticket_id', existing_type=sa.Integer(), nullable=True)

    create_table(
        'ticket_clarifications', sa.Column('id', sa.Integer(), primary_key=True),
        foreign('ticket_id', 'tickets', False), foreign('asked_by_user_id', 'users'),
        sa.Column('origin_status', sa.String(), nullable=False),
        sa.Column('question', sa.Text(), nullable=False), sa.Column('answer', sa.Text()),
        timestamp('created_at', False), timestamp('answered_at'),
    )
    create_table(
        'ticket_results', sa.Column('id', sa.Integer(), primary_key=True),
        foreign('ticket_id', 'tickets', False), foreign('submitted_by_user_id', 'users', False),
        foreign('confirmed_by_user_id', 'users'), sa.Column('description', sa.Text(), nullable=False),
        sa.Column('outcome', sa.Text(), nullable=False), timestamp('created_at', False),
        timestamp('confirmed_at'), timestamp('superseded_at'),
    )
    create_table(
        'ticket_refusals', sa.Column('id', sa.Integer(), primary_key=True),
        foreign('ticket_id', 'tickets', False), foreign('decided_by_user_id', 'users'),
        sa.Column('reason', sa.Text(), nullable=False), timestamp('created_at', False),
    )
    create_table(
        'ticket_appeals', sa.Column('id', sa.Integer(), primary_key=True),
        foreign('refusal_id', 'ticket_refusals', False), sa.Column('motivation', sa.Text(), nullable=False),
        foreign('admitted_by_user_id', 'users'), sa.Column('admission_decision', sa.String(), nullable=False),
        sa.Column('admission_reason', sa.Text()), foreign('manager_user_id', 'users'),
        foreign('admin_user_id', 'users'), sa.Column('manager_position', sa.String()),
        sa.Column('admin_position', sa.String()), sa.Column('manager_reason', sa.Text()),
        sa.Column('admin_reason', sa.Text()), sa.Column('joint_outcome', sa.String()),
        timestamp('created_at', False), timestamp('closed_at'),
    )
    for table, key in (
        ('ticket_clarifications', 'ticket_id'), ('ticket_results', 'ticket_id'),
        ('ticket_refusals', 'ticket_id'), ('ticket_appeals', 'refusal_id'),
    ):
        create_index(f'ix_{table}_{key}', table, [key])
    create_table(
        'routing_issues', sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('category', sa.String(), nullable=False), sa.Column('reason', sa.Text(), nullable=False),
        timestamp('created_at', False),
    )

    op.execute("""
        INSERT INTO department_members (user_id, department_id, role, office, valid_from)
        SELECT MIN(user_id), department_id, 'DEPARTMENT_MANAGER', TRUE, CURRENT_TIMESTAMP
        FROM (
            SELECT id AS user_id, department_id FROM users WHERE role = 'DEPARTMENT_MANAGER' AND active
            UNION
            SELECT m.user_id, m.department_id FROM department_members m
            JOIN users u ON u.id = m.user_id WHERE m.role = 'DEPARTMENT_MANAGER' AND u.active
        ) candidates WHERE department_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM department_members current
            WHERE current.department_id = candidates.department_id AND current.role = 'DEPARTMENT_MANAGER'
                AND current.office AND current.valid_to IS NULL
        ) GROUP BY department_id
    """)
    op.execute("""
        UPDATE tickets SET
            category_id = (SELECT id FROM categories WHERE name = tickets.category),
            author_department_id = (SELECT department_id FROM users WHERE id = tickets.author_id)
    """)
    op.execute("""
        UPDATE tickets SET owner_id = (SELECT user_id FROM department_members
            WHERE department_id = tickets.department_id AND office AND valid_to IS NULL)
    """)
    op.execute("UPDATE tickets SET author_department_id = NULL WHERE token_hash IS NOT NULL")
    op.execute("UPDATE tickets SET status = 'NEW' WHERE status = 'PENDING_ROUTING'")
    op.execute("UPDATE tickets SET status = CASE WHEN department_id IS NULL THEN 'NEW' ELSE 'ASSIGNED' END WHERE status = 'REOPENED'")
    op.execute("""
        INSERT INTO ticket_refusals (ticket_id, reason, created_at)
        SELECT id, result, COALESCE((SELECT MAX(created_at) FROM ticket_status_history
            WHERE ticket_id = tickets.id AND event LIKE 'Статус: REJECTED%'), created_at)
        FROM tickets WHERE status = 'REJECTED'
            AND NOT EXISTS (SELECT 1 FROM ticket_refusals WHERE ticket_id = tickets.id)
    """)
    op.execute("""
        INSERT INTO ticket_clarifications (ticket_id, origin_status, question, created_at)
        SELECT id, CASE WHEN executor_id IS NULL THEN 'ASSIGNED' ELSE 'IN_PROGRESS' END,
            COALESCE((SELECT SUBSTR(event, LENGTH('Статус: NEEDS_INFO. ') + 1) FROM ticket_status_history
                WHERE ticket_id = tickets.id AND event LIKE 'Статус: NEEDS_INFO.%' ORDER BY id DESC LIMIT 1),
                'Уточните сведения по обращению'), created_at
        FROM tickets WHERE status = 'NEEDS_INFO'
            AND NOT EXISTS (SELECT 1 FROM ticket_clarifications WHERE ticket_id = tickets.id)
    """)


def downgrade():
    raise RuntimeError('Restore the pre-upgrade backup to retain the original workflow and records.')
