from __future__ import annotations

from dataclasses import dataclass

from passsage.logs_ui import _init_duckdb_connection


@dataclass(frozen=True)
class CacheKeyCandidate:
    host: str
    param: str
    distinct_values: int
    paths: int
    misses: int


def analyze_cache_fragmentation(
    bucket: str,
    prefix: str,
    start_date: str,
    end_date: str,
    min_distinct: int,
    min_paths: int,
    min_misses: int,
    top: int,
) -> list[CacheKeyCandidate]:
    conn = _init_duckdb_connection()

    base = prefix.strip("/")
    s3_glob = f"s3://{bucket}/{base}/**/*.parquet"
    source = f"read_parquet('{s3_glob}', hive_partitioning=true)"

    sql = f"""
        WITH cache_misses AS (
            SELECT host, path, query
            FROM {source}
            WHERE date >= '{start_date}'
              AND date <= '{end_date}'
              AND method = 'GET'
              AND cache_hit = false
              AND query IS NOT NULL
              AND query != ''
        ),
        exploded AS (
            SELECT
                host,
                path,
                unnest(string_split(query, '&')) AS param_pair
            FROM cache_misses
        ),
        parsed AS (
            SELECT
                host,
                path,
                lower(trim(string_split(param_pair, '=')[1])) AS param_name,
                CASE WHEN contains(param_pair, '=')
                     THEN string_split(param_pair, '=')[2]
                     ELSE '' END AS param_value
            FROM exploded
            WHERE param_pair != ''
        )
        SELECT
            host,
            param_name AS param,
            count(DISTINCT param_value) AS distinct_values,
            count(DISTINCT path) AS paths,
            count(*) AS misses
        FROM parsed
        WHERE param_name != ''
        GROUP BY host, param_name
        HAVING distinct_values >= {min_distinct}
           AND paths >= {min_paths}
           AND misses >= {min_misses}
        ORDER BY distinct_values DESC, misses DESC
        LIMIT {top}
    """

    result = conn.execute(sql)
    return [
        CacheKeyCandidate(
            host=row[0],
            param=row[1],
            distinct_values=row[2],
            paths=row[3],
            misses=row[4],
        )
        for row in result.fetchall()
    ]
