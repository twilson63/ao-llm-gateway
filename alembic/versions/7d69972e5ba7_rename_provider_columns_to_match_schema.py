"""Rename provider columns to match schema

Revision ID: 7d69972e5ba7
Revises: 002_add_provider_config
Create Date: 2026-02-21 15:34:10.928215

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7d69972e5ba7'
down_revision: Union[str, None] = '002_add_provider_config'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Check if we need to copy data from old columns to new columns
    # (migration may have partially run)
    op.execute("UPDATE providers SET encrypted_api_key = api_key_encrypted WHERE encrypted_api_key IS NULL AND api_key_encrypted IS NOT NULL")
    op.execute("UPDATE providers SET endpoint_url = base_url || endpoint_path WHERE endpoint_url IS NULL OR endpoint_url = ''")
    
    # Set default value for endpoint_url where NULL
    op.execute("UPDATE providers SET endpoint_url = '/v1/chat/completions' WHERE endpoint_url IS NULL OR endpoint_url = ''")
    
    # Drop old columns (if they still exist)
    try:
        op.drop_column('providers', 'api_key_encrypted')
    except Exception:
        pass  # Column may already be dropped
    
    try:
        op.drop_column('providers', 'endpoint_path')
    except Exception:
        pass  # Column may already be dropped


def downgrade() -> None:
    # Add back old columns
    op.add_column('providers', sa.Column('endpoint_path', sa.String(length=200), nullable=True))
    op.add_column('providers', sa.Column('api_key_encrypted', sa.Text(), nullable=True))
    
    # Copy data back
    op.execute("UPDATE providers SET api_key_encrypted = encrypted_api_key WHERE encrypted_api_key IS NOT NULL")
    op.execute("UPDATE providers SET endpoint_path = REPLACE(endpoint_url, base_url, '') WHERE endpoint_url IS NOT NULL AND base_url IS NOT NULL")
    
    # Set default for endpoint_path
    op.execute("UPDATE providers SET endpoint_path = '/v1/chat/completions' WHERE endpoint_path IS NULL OR endpoint_path = ''")
    
    # Drop new columns
    op.drop_column('providers', 'endpoint_url')
    op.drop_column('providers', 'encrypted_api_key')
