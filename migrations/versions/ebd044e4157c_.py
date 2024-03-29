"""empty message

Revision ID: ebd044e4157c
Revises: a5fc89b97a23
Create Date: 2024-01-15 01:32:38.633697

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ebd044e4157c'
down_revision = 'a5fc89b97a23'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('name', sa.String(length=120), nullable=True))
        batch_op.alter_column('hashed_password',
               existing_type=sa.VARCHAR(length=80),
               type_=sa.String(length=580),
               existing_nullable=False)
        batch_op.alter_column('salt',
               existing_type=sa.VARCHAR(length=80),
               type_=sa.String(length=580),
               existing_nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('salt',
               existing_type=sa.String(length=580),
               type_=sa.VARCHAR(length=80),
               existing_nullable=False)
        batch_op.alter_column('hashed_password',
               existing_type=sa.String(length=580),
               type_=sa.VARCHAR(length=80),
               existing_nullable=False)
        batch_op.drop_column('name')

    # ### end Alembic commands ###
