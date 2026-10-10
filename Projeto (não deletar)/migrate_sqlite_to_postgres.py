import os
import sqlite3
import sys
from pathlib import Path

import psycopg


BASE_DIR = Path(__file__).resolve().parent

DEFAULT_SQLITE = BASE_DIR / "hotel-antigo.db"

# Tabelas que serão migradas.
# QUARTOS fica propositalmente FORA porque o banco antigo
# não informa a qual hotel os quartos pertenciam.
TABLES = [
    "hoteis",
    "usuarios",
    "faixas_etarias",
]

# Usuário global antigo não será restaurado.
# O SaaS atual utiliza platform_admin.
EXCLUDED_OLD_USERNAMES = {
    "admin",
}


def get_database_url():
    database_url = os.environ.get("DATABASE_URL")

    if not database_url:
        raise RuntimeError(
            "DATABASE_URL não está definida nesta janela do CMD."
        )

    return database_url


def connect_postgres():
    database_url = get_database_url()

    return psycopg.connect(database_url)


def sqlite_tables(sqlite_conn):
    rows = sqlite_conn.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    ).fetchall()

    return [row[0] for row in rows]


def sqlite_columns(sqlite_conn, table):
    rows = sqlite_conn.execute(
        f'PRAGMA table_info("{table}")'
    ).fetchall()

    return [row[1] for row in rows]


def postgres_columns(pg_conn, table):
    with pg_conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = %s
            ORDER BY ordinal_position
            """,
            (table,),
        )

        return [row[0] for row in cur.fetchall()]


def postgres_count(pg_conn, table):
    with pg_conn.cursor() as cur:
        cur.execute(
            f'SELECT COUNT(*) FROM "{table}"'
        )
        return cur.fetchone()[0]


def sqlite_count(sqlite_conn, table):
    return sqlite_conn.execute(
        f'SELECT COUNT(*) FROM "{table}"'
    ).fetchone()[0]


def migrate_hoteis(sqlite_conn, pg_conn):
    print()
    print("=" * 70)
    print("MIGRANDO HOTEIS")
    print("=" * 70)

    old_columns = sqlite_columns(sqlite_conn, "hoteis")

    rows = sqlite_conn.execute(
        'SELECT * FROM "hoteis" ORDER BY id'
    ).fetchall()

    if not rows:
        print("Nenhum hotel encontrado.")
        return 0

    pg_columns = postgres_columns(pg_conn, "hoteis")

    common_columns = [
        column
        for column in old_columns
        if column in pg_columns
    ]

    if "id" not in common_columns:
        raise RuntimeError(
            "A tabela hoteis não possui a coluna id em comum."
        )

    column_sql = ", ".join(
        f'"{column}"' for column in common_columns
    )

    placeholders = ", ".join(
        ["%s"] * len(common_columns)
    )

    index_map = {
        column: old_columns.index(column)
        for column in common_columns
    }

    inserted = 0
    skipped = 0

    with pg_conn.cursor() as cur:
        for row in rows:
            values = [
                row[index_map[column]]
                for column in common_columns
            ]

            cur.execute(
                f"""
                INSERT INTO "hoteis" ({column_sql})
                VALUES ({placeholders})
                ON CONFLICT ("id") DO NOTHING
                """,
                values,
            )

            if cur.rowcount == 1:
                inserted += 1
            else:
                skipped += 1

    pg_conn.commit()

    print(f"Encontrados: {len(rows)}")
    print(f"Inseridos: {inserted}")
    print(f"Ignorados por conflito: {skipped}")

    return inserted


def migrate_usuarios(sqlite_conn, pg_conn):
    print()
    print("=" * 70)
    print("MIGRANDO USUARIOS DOS HOTEIS")
    print("=" * 70)

    old_columns = sqlite_columns(sqlite_conn, "usuarios")

    rows = sqlite_conn.execute(
        'SELECT * FROM "usuarios" ORDER BY id'
    ).fetchall()

    if not rows:
        print("Nenhum usuário encontrado.")
        return 0

    pg_columns = postgres_columns(pg_conn, "usuarios")

    common_columns = [
        column
        for column in old_columns
        if column in pg_columns
    ]

    if "id" not in common_columns:
        raise RuntimeError(
            "A tabela usuarios não possui a coluna id em comum."
        )

    if "username" not in common_columns:
        raise RuntimeError(
            "A tabela usuarios não possui a coluna username."
        )

    column_sql = ", ".join(
        f'"{column}"' for column in common_columns
    )

    placeholders = ", ".join(
        ["%s"] * len(common_columns)
    )

    index_map = {
        column: old_columns.index(column)
        for column in common_columns
    }

    inserted = 0
    skipped = 0
    excluded = 0

    with pg_conn.cursor() as cur:
        for row in rows:
            username = row[index_map["username"]]

            if str(username or "").strip().lower() in EXCLUDED_OLD_USERNAMES:
                print(
                    f"IGNORADO: usuário global antigo '{username}'"
                )
                excluded += 1
                continue

            values = [
                row[index_map[column]]
                for column in common_columns
            ]

            cur.execute(
                f"""
                INSERT INTO "usuarios" ({column_sql})
                VALUES ({placeholders})
                ON CONFLICT ("id") DO NOTHING
                """,
                values,
            )

            if cur.rowcount == 1:
                inserted += 1
                print(
                    f"IMPORTADO: usuário '{username}'"
                )
            else:
                skipped += 1
                print(
                    f"IGNORADO POR CONFLITO: usuário '{username}'"
                )

    pg_conn.commit()

    print()
    print(f"Encontrados: {len(rows)}")
    print(f"Inseridos: {inserted}")
    print(f"Ignorados por conflito: {skipped}")
    print(f"Ignorados por serem usuário global antigo: {excluded}")

    return inserted


def migrate_faixas_etarias(sqlite_conn, pg_conn):
    print()
    print("=" * 70)
    print("MIGRANDO FAIXAS ETARIAS")
    print("=" * 70)

    old_columns = sqlite_columns(
        sqlite_conn,
        "faixas_etarias",
    )

    rows = sqlite_conn.execute(
        'SELECT * FROM "faixas_etarias" ORDER BY id'
    ).fetchall()

    if not rows:
        print("Nenhuma faixa etária encontrada.")
        return 0

    pg_columns = postgres_columns(
        pg_conn,
        "faixas_etarias",
    )

    common_columns = [
        column
        for column in old_columns
        if column in pg_columns
    ]

    if "id" not in common_columns:
        raise RuntimeError(
            "A tabela faixas_etarias não possui a coluna id."
        )

    column_sql = ", ".join(
        f'"{column}"' for column in common_columns
    )

    placeholders = ", ".join(
        ["%s"] * len(common_columns)
    )

    index_map = {
        column: old_columns.index(column)
        for column in common_columns
    }

    inserted = 0
    skipped = 0

    with pg_conn.cursor() as cur:
        for row in rows:
            values = [
                row[index_map[column]]
                for column in common_columns
            ]

            cur.execute(
                f"""
                INSERT INTO "faixas_etarias" ({column_sql})
                VALUES ({placeholders})
                ON CONFLICT ("id") DO NOTHING
                """,
                values,
            )

            if cur.rowcount == 1:
                inserted += 1
            else:
                skipped += 1

    pg_conn.commit()

    print(f"Encontradas: {len(rows)}")
    print(f"Inseridas: {inserted}")
    print(f"Ignoradas por conflito: {skipped}")

    return inserted


def reset_sequence(pg_conn, table):
    """
    Ajusta a sequência PostgreSQL depois da importação
    para evitar conflito de IDs em novos cadastros.
    """

    with pg_conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_default
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = %s
              AND column_name = 'id'
            """,
            (table,),
        )

        result = cur.fetchone()

        if not result or not result[0]:
            return

        default_value = result[0]

        if "nextval" not in default_value:
            return

        cur.execute(
            f"""
            SELECT pg_get_serial_sequence(
                'public."{table}"',
                'id'
            )
            """
        )

        sequence_result = cur.fetchone()

        if not sequence_result or not sequence_result[0]:
            return

        sequence_name = sequence_result[0]

        cur.execute(
            f"""
            SELECT COALESCE(MAX(id), 0)
            FROM "{table}"
            """
        )

        max_id = cur.fetchone()[0]

        if max_id > 0:
            cur.execute(
                "SELECT setval(%s, %s, true)",
                (sequence_name, max_id),
            )
        else:
            cur.execute(
                "SELECT setval(%s, 1, false)",
                (sequence_name,),
            )


def show_summary(sqlite_conn, pg_conn):
    print()
    print()
    print("=" * 70)
    print("RESUMO FINAL DA MIGRAÇÃO")
    print("=" * 70)

    tables = [
        "hoteis",
        "usuarios",
        "faixas_etarias",
        "quartos",
        "hospedes",
        "reservas",
        "fluxo_caixa",
        "estoque",
        "ordens_servico",
    ]

    for table in tables:
        old_count = 0
        pg_count = 0

        if table in sqlite_tables(sqlite_conn):
            old_count = sqlite_count(
                sqlite_conn,
                table,
            )

        try:
            pg_count = postgres_count(
                pg_conn,
                table,
            )
        except Exception:
            pg_count = "N/A"

        print(
            f"{table:20} "
            f"SQLite antigo: {str(old_count):>5} | "
            f"PostgreSQL: {str(pg_count):>5}"
        )

    print()
    print("IMPORTANTE:")
    print("- Quartos e dados operacionais antigos (hóspedes, reservas, caixa, estoque, ordens e pedidos) NÃO foram migrados.")
    print("- O usuário global antigo 'admin' NÃO foi migrado.")
    print("- Nenhum dado do PostgreSQL foi apagado.")
    print("- Nenhuma tabela foi recriada.")
    print("- Nenhuma chamada a init_db() foi feita.")


def validate_expected_data(sqlite_conn, pg_conn):
    print()
    print("=" * 70)
    print("VALIDAÇÃO")
    print("=" * 70)

    all_ok = True
    tables = ("hoteis", "usuarios", "faixas_etarias")
    for table in tables:
        source_columns = sqlite_columns(sqlite_conn, table)
        target_columns = postgres_columns(pg_conn, table)
        common_columns = [name for name in source_columns if name in target_columns]
        if "id" not in common_columns:
            print(f"ERRO {table}: coluna id não encontrada nos dois bancos")
            all_ok = False
            continue

        source_rows = sqlite_conn.execute(f'SELECT * FROM "{table}" ORDER BY id').fetchall()
        checked = 0
        missing = 0
        mismatched = 0
        for source_row in source_rows:
            source_values = dict(zip(source_columns, tuple(source_row)))
            if table == "usuarios" and str(source_values.get("username") or "").strip().lower() in EXCLUDED_OLD_USERNAMES:
                continue
            checked += 1
            target_row = pg_conn.execute(
                f'SELECT * FROM "{table}" WHERE id = %s',
                (source_values["id"],),
            ).fetchone()
            if target_row is None:
                missing += 1
                continue
            target_values = dict(zip(target_columns, target_row))
            differing = [name for name in common_columns if source_values.get(name) != target_values.get(name)]
            if differing:
                mismatched += 1
                # Never print credential values while reporting migration issues.
                safe_columns = [name for name in differing if name not in ("password", "senha", "token", "secret")]
                print(f"DIVERGÊNCIA {table} id={source_values['id']}: colunas {', '.join(safe_columns) or '[campo sensível]'}")

        if not missing and not mismatched:
            print(f"OK   {table}: {checked} registros de origem conferidos")
        else:
            print(f"ERRO {table}: {missing} ausentes, {mismatched} divergentes entre {checked} registros conferidos")
            all_ok = False

    return all_ok


def main():
    print()
    print("=" * 70)
    print("MIGRACAO SEGURA DO SQLITE ANTIGO PARA POSTGRESQL")
    print("=" * 70)
    print()
    print("ATENCAO:")
    print("- hotel-antigo.db sera usado somente como fonte.")
    print("- O PostgreSQL atual NAO sera apagado.")
    print("- Quartos e dados operacionais antigos NAO serao migrados por este script.")
    print("- O usuario global antigo 'admin' NAO sera migrado.")
    print()

    sqlite_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else DEFAULT_SQLITE
    )

    if not sqlite_path.exists():
        raise FileNotFoundError(
            f"Banco SQLite nao encontrado: {sqlite_path}"
        )

    print(
        f"Fonte SQLite: {sqlite_path}"
    )

    sqlite_conn = sqlite3.connect(
        sqlite_path
    )

    pg_conn = None

    try:
        pg_conn = connect_postgres()

        print(
            "PostgreSQL: conexao realizada com sucesso."
        )

        source_tables = sqlite_tables(
            sqlite_conn
        )

        print()
        print(
            "Tabelas encontradas no SQLite:"
        )

        for table in source_tables:
            print(
                f"  - {table}"
            )

        print()
        print(
            "Iniciando migracao..."
        )

        migrate_hoteis(
            sqlite_conn,
            pg_conn,
        )

        migrate_usuarios(
            sqlite_conn,
            pg_conn,
        )

        migrate_faixas_etarias(
            sqlite_conn,
            pg_conn,
        )

        # Os quartos ficam propositalmente fora.
        print()
        print("=" * 70)
        print("QUARTOS")
        print("=" * 70)
        print(
            "10 quartos encontrados no SQLite."
        )
        print(
            "NAO MIGRADOS porque o banco antigo nao informa "
            "a qual hotel pertencem."
        )

        # Ajusta sequências das tabelas importadas.
        for table in [
            "hoteis",
            "usuarios",
            "faixas_etarias",
        ]:
            try:
                reset_sequence(
                    pg_conn,
                    table,
                )
            except Exception as exc:
                print(
                    f"Aviso ao ajustar sequência de {table}: {exc}"
                )

        pg_conn.commit()

        show_summary(
            sqlite_conn,
            pg_conn,
        )

        ok = validate_expected_data(sqlite_conn, pg_conn)

        print()
        print("=" * 70)

        if ok:
            print(
                "RESULTADO: MIGRACAO CONCLUIDA COM SUCESSO"
            )
        else:
            print(
                "RESULTADO: REVISAR DADOS"
            )

        print("=" * 70)

    except Exception:
        if pg_conn:
            pg_conn.rollback()

        raise

    finally:
        sqlite_conn.close()

        if pg_conn:
            pg_conn.close()


if __name__ == "__main__":
    main()
