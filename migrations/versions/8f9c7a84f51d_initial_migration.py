"""Initial migration

Revision ID: 8f9c7a84f51d
Revises: 419229f07f25
Create Date: 2025-03-26 21:11:24.116909

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8f9c7a84f51d'
down_revision = '419229f07f25'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('bairro')
        batch_op.drop_column('data_nascimento')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('data_nascimento', sa.DATE(), nullable=True))
        batch_op.add_column(sa.Column('bairro', sa.VARCHAR(length=100), nullable=True))

    # ### end Alembic commands ###
