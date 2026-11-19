"""Initial database schema for central license server.

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-11-19 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. licenses table
    op.create_table(
        'licenses',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('key_hash', sa.String(length=64), nullable=False),
        sa.Column('license_type', sa.String(length=20), nullable=False, server_default='TRIAL'),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='UNUSED'),
        sa.Column('trial_duration_minutes', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('activation_limit', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata_json', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_licenses_id', 'licenses', ['id'], unique=False)
    op.create_index('ix_licenses_key_hash', 'licenses', ['key_hash'], unique=True)
    op.create_index('ix_licenses_status', 'licenses', ['status'], unique=False)

    # 2. devices table
    op.create_table(
        'devices',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_fingerprint_hash', sa.String(length=64), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='ACTIVE'),
        sa.Column('metadata_json', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_devices_id', 'devices', ['id'], unique=False)
    op.create_index('ix_devices_device_fingerprint_hash', 'devices', ['device_fingerprint_hash'], unique=True)

    # 3. activations table
    op.create_table(
        'activations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('license_id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('trial_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='ACTIVE'),
        sa.Column('last_verified_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ),
        sa.ForeignKeyConstraint(['license_id'], ['licenses.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_activations_id', 'activations', ['id'], unique=False)
    op.create_index('ix_activations_license_id', 'activations', ['license_id'], unique=False)
    op.create_index('ix_activations_device_id', 'activations', ['device_id'], unique=False)
    op.create_index('ix_activations_status', 'activations', ['status'], unique=False)
    op.create_index('idx_active_license_device', 'activations', ['license_id', 'device_id'], unique=False)

    # 4. device_trial_history table
    op.create_table(
        'device_trial_history',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('first_trial_started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('trial_consumed', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_device_trial_history_id', 'device_trial_history', ['id'], unique=False)
    op.create_index('ix_device_trial_history_device_id', 'device_trial_history', ['device_id'], unique=True)

    # 5. admin_users table
    op.create_table(
        'admin_users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('password_hash', sa.String(length=128), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False, server_default='admin'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_admin_users_id', 'admin_users', ['id'], unique=False)
    op.create_index('ix_admin_users_username', 'admin_users', ['username'], unique=True)

    # 6. audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('actor', sa.String(length=100), nullable=False, server_default='system'),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('target_id', sa.String(length=100), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('details_json', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_logs_id', 'audit_logs', ['id'], unique=False)
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'], unique=False)

    # 7. rate_limit_entries table
    op.create_table(
        'rate_limit_entries',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('bucket_key', sa.String(length=120), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_rate_limit_entries_id', 'rate_limit_entries', ['id'], unique=False)
    op.create_index('ix_rate_limit_entries_bucket_key', 'rate_limit_entries', ['bucket_key'], unique=False)
    op.create_index('ix_rate_limit_entries_timestamp', 'rate_limit_entries', ['timestamp'], unique=False)

    # 8. admin_lockout_entries table
    op.create_table(
        'admin_lockout_entries',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('client_ip', sa.String(length=64), nullable=False),
        sa.Column('failed_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_admin_lockout_entries_id', 'admin_lockout_entries', ['id'], unique=False)
    op.create_index('ix_admin_lockout_entries_client_ip', 'admin_lockout_entries', ['client_ip'], unique=True)


def downgrade() -> None:
    op.drop_table('admin_lockout_entries')
    op.drop_table('rate_limit_entries')
    op.drop_table('audit_logs')
    op.drop_table('admin_users')
    op.drop_table('device_trial_history')
    op.drop_table('activations')
    op.drop_table('devices')
    op.drop_table('licenses')
