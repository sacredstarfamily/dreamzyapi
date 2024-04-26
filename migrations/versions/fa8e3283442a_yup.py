"""yup

Revision ID: fa8e3283442a
Revises: b5e1f011307c
Create Date: 2024-04-25 18:11:05.627161

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fa8e3283442a'
down_revision = 'b5e1f011307c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('dream', schema=None) as batch_op:
        batch_op.add_column(sa.Column('likes', sa.Integer(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('dream', schema=None) as batch_op:
        batch_op.drop_column('likes')

    # ### end Alembic commands ###