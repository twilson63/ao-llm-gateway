"""Add provider configuration fields

Revision ID: 002_add_provider_config
Revises: 001_initial
Create Date: 2026-02-21 11:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '002_add_provider_config'
down_revision: Union[str, None] = '001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new columns to providers table
    op.add_column('providers', sa.Column('endpoint_path', sa.String(200), nullable=False, server_default='/v1/chat/completions'))
    op.add_column('providers', sa.Column('auth_type', sa.String(20), nullable=False, server_default='bearer'))
    op.add_column('providers', sa.Column('auth_header_name', sa.String(50), nullable=True))
    op.add_column('providers', sa.Column('header_mapping', sa.Text(), nullable=True))
    op.add_column('providers', sa.Column('request_transform', sa.Text(), nullable=True))
    op.add_column('providers', sa.Column('response_transform', sa.Text(), nullable=True))
    op.add_column('providers', sa.Column('timeout_seconds', sa.Integer(), nullable=False, server_default='60'))
    op.add_column('providers', sa.Column('retry_count', sa.Integer(), nullable=False, server_default='3'))
    
    # Create index on auth_type
    op.create_index('ix_providers_auth_type', 'providers', ['auth_type'])
    
    # Add new columns to provider_models table
    op.add_column('provider_models', sa.Column('endpoint_override', sa.String(200), nullable=True))
    op.add_column('provider_models', sa.Column('model_config', sa.Text(), nullable=True))
    
    # Create index on provider_id in provider_models
    op.create_index('ix_provider_models_provider_id', 'provider_models', ['provider_id'])
    
    # Migrate existing data - set default values for providers
    op.execute("UPDATE providers SET endpoint_path = '/v1/chat/completions' WHERE endpoint_path IS NULL")
    op.execute("UPDATE providers SET auth_type = 'bearer' WHERE auth_type IS NULL")
    op.execute("UPDATE providers SET timeout_seconds = 60 WHERE timeout_seconds IS NULL")
    op.execute("UPDATE providers SET retry_count = 3 WHERE retry_count IS NULL")


def downgrade() -> None:
    # Drop indexes
    op.drop_index('ix_provider_models_provider_id', table_name='provider_models')
    op.drop_index('ix_providers_auth_type', table_name='providers')
    
    # Remove columns from provider_models (data will be lost)
    op.drop_column('provider_models', 'model_config')
    op.drop_column('provider_models', 'endpoint_override')
    
    # Remove columns from providers (data will be lost)
    op.drop_column('providers', 'retry_count')
    op.drop_column('providers', 'timeout_seconds')
    op.drop_column('providers', 'response_transform')
    op.drop_column('providers', 'request_transform')
    op.drop_column('providers', 'header_mapping')
    op.drop_column('providers', 'auth_header_name')
    op.drop_column('providers', 'auth_type')
    op.drop_column('providers', 'endpoint_path')
