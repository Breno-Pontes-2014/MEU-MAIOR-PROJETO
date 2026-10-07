import os
import sys
from pathlib import Path
import sqlite3
import psycopg

BASE_DIR = Path(__file__).resolve().parent

TABLES = [
    "hoteis","usuarios","tipos_quarto","quartos","hospedes","faixas_etarias",
    "reservas","estoque","fluxo_caixa","ordens_servico","planos","assinaturas",
    "hotel_integracoes","webhook_eventos","servicos","pedidos_hospede"
]

TENANT_TABLES = [
    "tipos_quarto","quartos","hospedes","faixas_etarias","reservas",
    "estoque","fluxo_caixa","ordens_servico","hotel_integracoes",
    "webhook_eventos","servicos","pedidos_hospede"
]

def pass_fail(ok, mensagem):
    print(("OK    " if ok else "FALHA ") + mensagem)
    return ok

def postgres_counts(conn):
    out = {}
    with conn.cursor() as cur:
        for table in TABLES:
            cur.execute(
                """SELECT COUNT(*) FROM information_schema.tables
                   WHERE table_schema=current_schema() AND table_name=%s""",
                (table,)
            )
            if cur.fetchone()[0] == 0:
                out[table] = None
                continue
            cur.execute(f'SELECT COUNT(*) FROM "{table}"')
            out[table] = cur.fetchone()[0]
    return out

def check_schema(conn):
    ok = True
    with conn.cursor() as cur:
        for table in TABLES:
            cur.execute(
                """SELECT 1 FROM information_schema.tables
                   WHERE table_schema=current_schema() AND table_name=%s""",
                (table,)
            )
            if cur.fetchone() is None:
                ok = pass_fail(False, f"tabela ausente: {table}") and ok
            else:
                ok = pass_fail(True, f"tabela presente: {table}") and ok
    return ok

def check_tenant_integrity(conn):
    ok = True
    checks = [
        (
            "usuarios sem hotel e que não são platform_admin",
            """SELECT COUNT(*) FROM usuarios
               WHERE hotel_id IS NULL AND role <> 'platform_admin'"""
        ),
        (
            "quartos sem hotel",
            """SELECT COUNT(*) FROM quartos WHERE hotel_id IS NULL"""
        ),
        (
            "hospedes sem hotel",
            """SELECT COUNT(*) FROM hospedes WHERE hotel_id IS NULL"""
        ),
        (
            "reservas com hóspede inexistente no mesmo hotel",
            """SELECT COUNT(*) FROM reservas r
               LEFT JOIN hospedes h
                 ON h.id=r.hospede_id AND h.hotel_id=r.hotel_id
               WHERE r.hospede_id IS NOT NULL AND h.id IS NULL"""
        ),
        (
            "reservas com quarto inexistente no mesmo hotel",
            """SELECT COUNT(*) FROM reservas r
               LEFT JOIN quartos q
                 ON q.numero=r.quarto_numero AND q.hotel_id=r.hotel_id
               WHERE r.quarto_numero IS NOT NULL AND q.id IS NULL"""
        ),
        (
            "pedidos com quarto inexistente no mesmo hotel",
            """SELECT COUNT(*) FROM pedidos_hospede p
               LEFT JOIN quartos q
                 ON q.id=p.quarto_id AND q.hotel_id=p.hotel_id
               WHERE p.quarto_id IS NOT NULL AND q.id IS NULL"""
        ),
        (
            "ordens com quarto inexistente no mesmo hotel",
            """SELECT COUNT(*) FROM ordens_servico o
               LEFT JOIN quartos q
                 ON q.id=o.quarto_id AND q.hotel_id=o.hotel_id
               WHERE o.quarto_id IS NOT NULL AND q.id IS NULL"""
        ),
        (
            "serviços duplicados por hotel",
            """SELECT COUNT(*) FROM (
                 SELECT hotel_id,nome,COUNT(*)
                 FROM servicos
                 GROUP BY hotel_id,nome
                 HAVING COUNT(*) > 1
               ) x"""
        ),
    ]
    with conn.cursor() as cur:
        for label, sql in checks:
            cur.execute(sql)
            count = cur.fetchone()[0]
            ok = pass_fail(count == 0, f"{label}: {count}") and ok
    return ok

def compare_sqlite(conn_pg, sqlite_path):
    if not sqlite_path.exists():
        return pass_fail(False, f"SQLite não encontrado: {sqlite_path}")
    src = sqlite3.connect(str(sqlite_path))
    try:
        ok = True
        for table in TABLES:
            exists = src.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
                (table,)
            ).fetchone()[0]
            if not exists:
                print(f"INFO  tabela não existe no SQLite de origem: {table}")
                continue
            src_count = src.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            with conn_pg.cursor() as cur:
                cur.execute(f'SELECT COUNT(*) FROM "{table}"')
                pg_count = cur.fetchone()[0]
            ok = pass_fail(src_count == pg_count,
                            f"contagem {table}: SQLite={src_count} PostgreSQL={pg_count}") and ok
        return ok
    finally:
        src.close()

def main():
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        raise SystemExit("Defina DATABASE_URL com a conexão do PostgreSQL.")

    sqlite_arg = sys.argv[1] if len(sys.argv) > 1 else None
    sqlite_path = Path(sqlite_arg) if sqlite_arg else None

    try:
        conn = psycopg.connect(url)
    except Exception as exc:
        raise SystemExit(f"Não foi possível conectar ao PostgreSQL: {exc}")

    try:
        print("=== VALIDAÇÃO POSTGRESQL ===")
        with conn.cursor() as cur:
            cur.execute("SELECT current_database(), current_schema(), version()")
            db, schema, version = cur.fetchone()
        pass_fail(True, f"conexão: banco={db}, schema={schema}")
        print(version.split(",")[0])

        schema_ok = check_schema(conn)
        counts = postgres_counts(conn)
        print("\n=== CONTAGENS NO POSTGRESQL ===")
        for table, count in counts.items():
            print(f"{table}: {'AUSENTE' if count is None else count}")

        integrity_ok = check_tenant_integrity(conn)

        compare_ok = True
        if sqlite_path:
            print("\n=== COMPARAÇÃO COM SQLITE ===")
            compare_ok = compare_sqlite(conn, sqlite_path)

        final_ok = schema_ok and integrity_ok and compare_ok
        print("\nRESULTADO FINAL:", "APROVADO" if final_ok else "REVISAR")
        raise SystemExit(0 if final_ok else 1)
    finally:
        conn.close()

if __name__ == "__main__":
    main()
