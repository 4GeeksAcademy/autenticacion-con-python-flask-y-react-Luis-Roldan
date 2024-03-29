"""empty message

Revision ID: a5fc89b97a23
Revises: 110f0c2bf52f
Create Date: 2024-01-14 23:33:11.621638

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a5fc89b97a23'
down_revision = '110f0c2bf52f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('hashed_password', sa.String(length=80), nullable=False))
        batch_op.add_column(sa.Column('salt', sa.String(length=80), nullable=False))
        batch_op.drop_column('is_active')
        batch_op.drop_column('password')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('password', sa.VARCHAR(length=80), autoincrement=False, nullable=False))
        batch_op.add_column(sa.Column('is_active', sa.BOOLEAN(), autoincrement=False, nullable=False))
        batch_op.drop_column('salt')
        batch_op.drop_column('hashed_password')

    # ### end Alembic commands ###
