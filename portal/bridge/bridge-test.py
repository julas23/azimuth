#!/usr/bin/env python3
"""Testes de integração do vpn-bridge — roda como root após o serviço subir."""

import json
import socket
import sys

SOCK = "/run/vpn-bridge/bridge.sock"


def call(action: str, **kwargs) -> dict:
    req = json.dumps({"action": action, **kwargs}).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK)
        s.sendall(req)
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while chunk := s.recv(4096):
            chunks.append(chunk)
    resp = json.loads(b"".join(chunks))
    status = "✓" if resp.get("ok") else "✗"
    print(f"  {status} [{action}] {json.dumps(resp)}")
    return resp


def section(title: str) -> None:
    print(f"\n── {title} {'─' * (50 - len(title))}")


def main() -> None:
    errors = 0

    section("genkeys")
    r = call("genkeys")
    if not r["ok"]:
        print("FATAL: genkeys falhou"); sys.exit(1)
    pubkey = r["pubkey"]

    section("add_peer")
    r = call("add_peer", pubkey=pubkey, ip="10.50.0.250", label="teste-integracao")
    if not r["ok"]: errors += 1

    section("get_stats (sem handshake — ok=False esperado)")
    call("get_stats", pubkey=pubkey)  # peer recém-criado, sem handshake ainda

    section("set_quota")
    r = call("set_quota", ip="10.50.0.250")
    if not r["ok"]: errors += 1

    section("clear_quota")
    r = call("clear_quota", ip="10.50.0.250")
    if not r["ok"]: errors += 1

    section("remove_peer")
    r = call("remove_peer", pubkey=pubkey)
    if not r["ok"]: errors += 1

    section("resolve_whitelist")
    r = call("resolve_whitelist", domains=["one.one.one.one", "google.com"])
    if not r["ok"]: errors += 1

    section("validações — entradas inválidas")
    r = call("add_peer", pubkey="chave-invalida", ip="10.50.0.1")
    if r["ok"]: errors += 1  # deve rejeitar
    else: print(f"  ✓ pubkey inválida rejeitada corretamente")

    r = call("set_quota", ip="192.168.1.1")
    if r["ok"]: errors += 1  # IP fora dos subnets VPN
    else: print(f"  ✓ IP fora de subnet rejeitado corretamente")

    r = call("remove_peer", pubkey="A" * 43 + "=")
    if not r["ok"]: errors += 1  # wg remove é idempotente — peer inexistente retorna ok
    else: print(f"  ✓ remove de peer inexistente é idempotente (correto)")

    section("ação desconhecida")
    r = call("acao-que-nao-existe")
    if r["ok"]: errors += 1
    else: print(f"  ✓ ação inválida rejeitada corretamente")

    print(f"\n{'─' * 55}")
    if errors == 0:
        print("✓ Todos os testes passaram")
    else:
        print(f"✗ {errors} teste(s) falharam")
        sys.exit(1)


if __name__ == "__main__":
    main()
