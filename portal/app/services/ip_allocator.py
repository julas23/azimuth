"""
IP allocator: finds the next free address in a plan's /16 subnet.

Uses SELECT FOR UPDATE on the plans row as a per-plan mutex so two
concurrent registrations never hand out the same IP.
"""
import ipaddress
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from models.plan import Plan
from models.peer import VpnPeer

# .1 is the gateway — first allocatable offset
_FIRST_OFFSET = 2


async def allocate_ip(db: AsyncSession, plan_id: str) -> str:
    """
    Returns the next free IPv4 address in the plan's subnet as a string.
    Raises RuntimeError when the subnet is exhausted.
    Must be called inside an open transaction.
    """
    # Lock the plan row to serialize concurrent allocations
    result = await db.execute(
        select(Plan).where(Plan.id == plan_id).with_for_update()
    )
    plan: Plan | None = result.scalar_one_or_none()
    if plan is None:
        raise ValueError(f"Plan '{plan_id}' not found")

    network = ipaddress.ip_network(plan.subnet, strict=False)

    # Fetch every IP ever assigned — the unique constraint is global, and plan_id
    # on a peer can drift after plan changes, so we must check the full table.
    rows = await db.execute(select(VpnPeer.ip_address))
    used = {str(row[0]) for row in rows}

    hosts = network.hosts()
    # Skip .1 (gateway)
    for _ in range(_FIRST_OFFSET - 1):
        next(hosts, None)

    for host in hosts:
        candidate = str(host)
        if candidate not in used:
            return candidate

    raise RuntimeError(f"Subnet {plan.subnet} is exhausted (plan '{plan_id}')")
