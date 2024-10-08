"""Add has_voted to User model

Revision ID: 3a50e05197ee
Revises: 77e5f9ac1766
Create Date: 2024-09-18 13:15:38.499422

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3a50e05197ee'
down_revision = '77e5f9ac1766'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('has_voted', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('has_voted')

    # ### end Alembic commands ###
