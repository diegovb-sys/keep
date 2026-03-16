"""
Db2Provider is a class that provides a way to read data from IBM DB2 and write queries to DB2.
"""

import dataclasses
import datetime
import os
import pydantic

from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig, ProviderScope
from keep.providers.models.provider_method import ProviderMethod
from keep.validation.fields import NoSchemeUrl, UrlPort


# Lazy import of ibm_db to avoid fork issues with gunicorn workers
# ibm_db is a C extension that doesn't work well with process forking
# We use lazy loading so each worker process imports its own clean copy after forking


@pydantic.dataclasses.dataclass
class Db2ProviderAuthConfig:
    username: str = dataclasses.field(
        metadata={"required": True, "description": "DB2 username"}
    )
    password: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "DB2 password",
            "sensitive": True,
        }
    )
    host: NoSchemeUrl = dataclasses.field(
        metadata={
            "required": True,
            "description": "DB2 hostname",
            "validation": "no_scheme_url",
        }
    )
    database: str = dataclasses.field(
        metadata={"required": True, "description": "DB2 database name"}
    )
    port: UrlPort | None = dataclasses.field(
        default=50000,
        metadata={
            "required": False,
            "description": "DB2 port",
            "validation": "port",
        },
    )
    protocol: str | None = dataclasses.field(
        default="TCPIP",
        metadata={
            "required": False,
            "description": "DB2 protocol (default: TCPIP)",
        },
    )


class Db2Provider(BaseProvider):
    """Enrich alerts with data from IBM DB2."""

    PROVIDER_DISPLAY_NAME = "IBM DB2"
    PROVIDER_CATEGORY = ["Database"]
    PROVIDER_SCOPES = [
        ProviderScope(
            name="connect_to_server",
            description="The user can connect to the server",
            mandatory=True,
            alias="Connect to the server",
        )
    ]
    PROVIDER_METHODS = [
        ProviderMethod(
            name="query",
            func_name="execute_query",
            description="Query the DB2 database",
            type="view",
        )
    ]

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)
        self.conn = None
        # Lazy loading: modules are imported only when first needed
        self._ibm_db = None
        self._ibm_db_dbi = None

    def _ensure_modules_loaded(self):
        """
        Lazy loads ibm_db modules only when first needed.
        This avoids fork issues with gunicorn workers since the C extension
        is imported in the worker process, not in the parent before forking.

        Returns:
            tuple: (ibm_db, ibm_db_dbi) modules
        """
        if self._ibm_db is None:
            import ibm_db
            import ibm_db_dbi
            self._ibm_db = ibm_db
            self._ibm_db_dbi = ibm_db_dbi
        return self._ibm_db, self._ibm_db_dbi

    def validate_scopes(self):
        """
        Validates that the user has the required scopes to use the provider.
        """
        try:
            ibm_db, _ = self._ensure_modules_loaded()
            conn = self.__generate_connection()
            ibm_db.close(conn)
            scopes = {
                "connect_to_server": True,
            }
        except Exception as e:
            self.logger.exception("Error validating scopes")
            scopes = {
                "connect_to_server": str(e),
            }
        return scopes

    def execute_query(self, query: str):
        return self._query(query)

    def __generate_connection(self):
        """
        Generates a DB2 connection.

        Returns:
            ibm_db connection object
        """
        ibm_db, _ = self._ensure_modules_loaded()

        # Build connection string
        conn_str = (
            f"DATABASE={self.authentication_config.database};"
            f"HOSTNAME={self.authentication_config.host};"
            f"PORT={self.authentication_config.port};"
            f"PROTOCOL={self.authentication_config.protocol};"
            f"UID={self.authentication_config.username};"
            f"PWD={self.authentication_config.password};"
        )

        conn = ibm_db.connect(conn_str, "", "")
        return conn

    def dispose(self):
        try:
            if self.conn:
                ibm_db, _ = self._ensure_modules_loaded()
                ibm_db.close(self.conn)
        except Exception:
            self.logger.exception("Error closing DB2 connection")

    def validate_config(self):
        """
        Validates required configuration for DB2's provider.
        """
        self.authentication_config = Db2ProviderAuthConfig(
            **self.config.authentication
        )

    def _notify(self, query: str, **kwargs):
        """
        For DB2 there is no difference if we're querying data or we want to make an impact.
        This will allow using the provider in actions as well as steps.
        Args:
            query (str): Query to execute
            **kwargs: Arguments will be passed to the query.format(**kwargs)
        """
        return self._query(query, **kwargs)

    def _query(
        self, query="", as_dict=False, **kwargs: dict
    ) -> list | tuple:
        """
        Executes a query against the DB2 database.
        Args:
            query (str): Query to execute
            as_dict (bool): If True, returns the results as a list of dictionaries
            **kwargs: Arguments will be passed to the query.format(**kwargs)

        Returns:
            list | tuple: list of results or single result if single_row is True
        """
        if not query:
            raise ValueError("Query is required")

        ibm_db, ibm_db_dbi = self._ensure_modules_loaded()

        conn = self.__generate_connection()

        try:
            # Format query with kwargs if provided
            if kwargs:
                query = query.format(**kwargs)

            # Use ibm_db_dbi for easier Python DB-API 2.0 interface
            pconn = ibm_db_dbi.Connection(conn)
            cursor = pconn.cursor()
            cursor.execute(query)

            # Commit if this is a write operation (INSERT, UPDATE, DELETE)
            if query.strip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
                pconn.commit()

            # Fetch results
            results = cursor.fetchall()

            if as_dict and results:
                column_names = [desc[0] for desc in cursor.description]
                results = [
                    {
                        key: (value.isoformat() if isinstance(value, datetime.datetime) else value)
                        for key, value in dict(zip(column_names, row)).items()
                    }
                    for row in results
                ]

            cursor.close()

            return results
        finally:
            ibm_db.close(conn)


if __name__ == "__main__":
    config = ProviderConfig(
        authentication={
            "username": os.getenv("DB2_USER"),
            "password": os.getenv("DB2_PASSWORD"),
            "host": os.getenv("DB2_HOST"),
            "database": os.getenv("DB2_DATABASE"),
            "port": os.getenv("DB2_PORT"),
        }
    )
    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )
    db2_provider = Db2Provider(context_manager, "db2-prod", config)
    results = db2_provider.query(query="SELECT * FROM SYSIBM.SYSTABLES FETCH FIRST 5 ROWS ONLY")
    print(results)
