import os
import sqlite3
import sys
from pathlib import Path
import psycopg

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_SQLITE = BASE_DIR / "hotel.db"

TABLES = [
    "hoteis", "usuarios", "tipos_quarto", "quartos", "hospedes",
    "faixas_etarias", "reservas", "estoque", "fluxo_caixa",
    "ordens_servico", "planos", "assinaturas", "hotel_integracoes",
    "webhook_eventos"
]

def sqlite_tables(conn):
    return {
        row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }

def sqlite_columns(conn, table):
    return [
        row[1] for row in conn.execute(
            f'PRAGMA table_info("{table}")'
        ).fetchall()
    ]

def postgres_columns(conn, table):
    with conn.cursor() as cur:
        cur.execute(
            """SELECT column_name
               FROM information_schema.columns
               WHERE table_schema=current_schema()
                 AND table_name=%s
               ORDER BY ordinal_position""",
            (table,)
        )
        return [r[0] for r in cur.fetchall()]

def reset_sequences(conn):
    for table in TABLES:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT pg_get_serial_sequence(%s, 'id')""",
                (table,)
            )
            row = cur.fetchone()
            sequence = row[0] if row else None
            if not sequence:
                continue

            cur.execute(f'SELECT MAX(id) FROM "{table}"')
            max_id = cur.fetchone()[0]
            if max_id is not None:
                cur.execute(
                    "SELECT setval(%s, %s, true)",
                    (sequence, max_id)
                )
    conn.commit()

def migrate():
    target = os.getenv("DATABASE_URL", "").strip()
    if not target:
        raise SystemExit("Defina DATABASE_URL apontando para o PostgreSQL de destino.")

    sqlite_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SQLITE
    if not sqlite_path.exists():
        raise SystemExit(f"Banco SQLite não encontrado: {sqlite_path}")

    # O app cria o schema PostgreSQL antes de copiar os dados.
    os.environ["DATABASE_URL"] = target
    sys.path.insert(0, str(BASE_DIR))
    from app import init_db
    init_db()

    src = sqlite3.connect(str(sqlite_path))
    src.row_factory = sqlite3.Row
    dst = psycopg.connect(target)

    try:
        source_tables = sqlite_tables(src)

        # Se o SQLite antigo não possuía hotel_id, os dados antigos
        # ficam associados ao primeiro hotel cadastrado.
        first_hotel = (
            src.execute("SELECT id FROM hoteis ORDER BY id LIMIT 1").fetchone()
            if "hoteis" in source_tables else None
        )
        default_hotel_id = first_hotel["id"] if first_hotel else None

        for table in TABLES:
            if table not in source_tables:
                continue

            source_cols = sqlite_columns(src, table)
            target_cols = postgres_columns(dst, table)
            common = [col for col in source_cols if col in target_cols]

            if "hotel_id" in target_cols and "hotel_id" not in common:
                common.append("hotel_id")

            if "id" not in common:
                print(f"Ignorado (sem id): {table}")
                continue

            rows = src.execute(
                f'SELECT {",".join([chr(34)+col+chr(34) for col in source_cols])} FROM "{table}"'
            ).fetchall()

            if not rows:
                continue

            cols_sql = ",".join(f'"{col}"' for col in common)
            placeholders = ",".join(["%s"] * len(common))
            update_cols = [col for col in common if col != "id"]

            if update_cols:
                updates = ",".join(
                    f'"{col}"=EXCLUDED."{col}"' for col in update_cols
                )
                sql = (
                    f'INSERT INTO "{table}" ({cols_sql}) '
                    f'VALUES ({placeholders}) '
                    f'ON CONFLICT ("id") DO UPDATE SET {updates}'
                )
            else:
                sql = (
                    f'INSERT INTO "{table}" ({cols_sql}) '
                    f'VALUES ({placeholders}) '
                    f'ON CONFLICT ("id") DO NOTHING'
                )

            with dst.cursor() as cur:
                for row in rows:
                    values = []
                    for col in common:
                        if col in source_cols:
                            values.append(row[col])
                        else:
                            values.append(default_hotel_id)
                    cur.execute(sql, values)

            dst.commit()
            print(f"Migrado: {table} ({len(rows)} registros)")

        reset_sequences(dst)
        print("Migração SQLite -> PostgreSQL concluída.")

    finally:
        src.close()
        dst.close()

if __name__ == "__main__":
    migrate()
