import os
from logging.config import fileConfig

# Import all models to ensure metadata is fully populated
import backend.app.db.models  # noqa: F401
from alembic import context
from backend.app.core.config import settings
from backend.app.db.base import Base
from backend.app.db.session import get_engine

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Model metadata for autogenerate support
target_metadata = Base.metadata


def get_url() -> str:
    env_url = os.environ.get("DATABASE_URL")
    if env_url:
        return env_url
    url = config.get_main_option("sqlalchemy.url")
    return url if url and not url.startswith("driver://") else settings.DATABASE_URL


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # Crucial for SQLite ALTER operations
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    # Use centralized engine configuration with SQLite pragma support
    connectable = get_engine(get_url())

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # Enables batch mode for SQLite table alterations
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
