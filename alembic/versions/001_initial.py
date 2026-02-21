"""Initial migration - create all tables

Revision ID: 001_initial
Revises: 
Create Date: 2026-02-21 09:45:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('email', sa.String(255), nullable=False, unique=True),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
    )
    op.create_index('ix_users_email', 'users', ['email'])

    # Create access_keys table
    op.create_table(
        'access_keys',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), nullable=False),
        sa.Column('key_id', sa.String(36), nullable=False, unique=True),
        sa.Column('key_secret', sa.String(255), nullable=False),
        sa.Column('authority', sa.String(255), nullable=True),
        sa.Column('process_id', sa.String(255), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_access_keys_key_id', 'access_keys', ['key_id'])

    # Create providers table
    op.create_table(
        'providers',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(100), nullable=False, unique=True),
        sa.Column('display_name', sa.String(255), nullable=False),
        sa.Column('base_url', sa.String(500), nullable=False),
        sa.Column('api_key_encrypted', sa.Text(), nullable=True),
        sa.Column('default_headers', sa.Text(), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_providers_name', 'providers', ['name'])

    # Create provider_models table
    op.create_table(
        'provider_models',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('provider_id', sa.String(36), nullable=False),
        sa.Column('model_name', sa.String(100), nullable=False),
        sa.Column('display_name', sa.String(255), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['provider_id'], ['providers.id'], ondelete='CASCADE'),
    )

    # Create rate_limits table
    op.create_table(
        'rate_limits',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('process_id', sa.String(255), nullable=False, unique=True),
        sa.Column('requests_per_minute', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('requests_per_day', sa.Integer(), nullable=False, server_default='10000'),
        sa.Column('requests_minute_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('requests_day_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_minute_reset', sa.DateTime(), nullable=False),
        sa.Column('last_day_reset', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_rate_limits_process_id', 'rate_limits', ['process_id'])


def downgrade() -> None:
    op.drop_index('ix_rate_limits_process_id', table_name='rate_limits')
    op.drop_table('rate_limits')
    
    op.drop_table('provider_models')
    
    op.drop_index('ix_providers_name', table_name='providers')
    op.drop_table('providers')
    
    op.drop_index('ix_access_keys_key_id', table_name='access_keys')
    op.drop_table('access_keys')
    
    op.drop_index('ix_users_email', table_name='users')
    op.drop_table('users')
