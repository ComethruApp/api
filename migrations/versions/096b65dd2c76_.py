"""empty message

Revision ID: 096b65dd2c76
Revises: 
Create Date: 2019-10-26 09:46:13.045496

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '096b65dd2c76'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('blacklisted_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('token', sa.String(length=500), nullable=False),
    sa.Column('blacklisted_on', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token')
    )
    op.create_table('schools',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=True),
    sa.Column('nickname', sa.String(length=16), nullable=True),
    sa.Column('color', sa.String(length=6), nullable=True),
    sa.Column('domain', sa.String(length=32), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('domain'),
    sa.UniqueConstraint('name'),
    sa.UniqueConstraint('nickname')
    )
    op.create_table('events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=True),
    sa.Column('registered_on', sa.DateTime(), nullable=False),
    sa.Column('description', sa.String(length=1024), nullable=True),
    sa.Column('location_name', sa.String(length=127), nullable=True),
    sa.Column('location_lat', sa.Float(), nullable=True),
    sa.Column('location_lon', sa.Float(), nullable=True),
    sa.Column('time_start', sa.DateTime(), nullable=False),
    sa.Column('time_end', sa.DateTime(), nullable=True),
    sa.Column('venmo', sa.String(length=32), nullable=True),
    sa.Column('school_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['school_id'], ['schools.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=True),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password', sa.String(length=255), nullable=False),
    sa.Column('registered_on', sa.DateTime(), nullable=False),
    sa.Column('verified', sa.Boolean(), nullable=False),
    sa.Column('admin', sa.Boolean(), nullable=False),
    sa.Column('bio', sa.String(length=127), nullable=True),
    sa.Column('school_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['school_id'], ['schools.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('followers',
    sa.Column('follower_id', sa.Integer(), nullable=True),
    sa.Column('followed_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['followed_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['follower_id'], ['users.id'], )
    )
    op.create_table('hostships',
    sa.Column('host_id', sa.Integer(), nullable=True),
    sa.Column('event_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['event_id'], ['events.id'], ),
    sa.ForeignKeyConstraint(['host_id'], ['users.id'], )
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('hostships')
    op.drop_table('followers')
    op.drop_table('users')
    op.drop_table('events')
    op.drop_table('schools')
    op.drop_table('blacklisted_tokens')
    # ### end Alembic commands ###