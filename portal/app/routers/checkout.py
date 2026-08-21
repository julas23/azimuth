"""
POST /checkout/session — cria uma Stripe Checkout Session para assinatura.
"""
import stripe
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.plan import Plan
from models.user import User
from routers.auth import _get_current_user

router = APIRouter(prefix="/checkout", tags=["checkout"])


class CheckoutRequest(BaseModel):
    plan_id: str


class CheckoutResponse(BaseModel):
    url: str


@router.post("/session", response_model=CheckoutResponse)
async def create_checkout_session(
    body: CheckoutRequest,
    current_user: User = Depends(_get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CheckoutResponse:
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Pagamentos ainda não configurados")

    result = await db.execute(select(Plan).where(Plan.id == body.plan_id))
    plan = result.scalar_one_or_none()
    if plan is None:
        raise HTTPException(status_code=404, detail="Plano não encontrado")

    stripe.api_key = settings.STRIPE_SECRET_KEY

    # Cria ou reutiliza customer Stripe
    customer_id = current_user.stripe_customer_id
    if not customer_id:
        customer = stripe.Customer.create(
            email=current_user.email,
            name=current_user.name,
            metadata={"user_id": str(current_user.id)},
        )
        customer_id = customer.id
        from sqlalchemy import update
        from models.user import User as UserModel
        await db.execute(
            update(UserModel)
            .where(UserModel.id == current_user.id)
            .values(stripe_customer_id=customer_id)
        )
        await db.commit()

    session = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": plan.stripe_price_id, "quantity": 1}],
        metadata={"user_id": str(current_user.id), "plan_id": plan.id},
        success_url=f"{settings.APP_BASE_URL}/dashboard?checkout=success",
        cancel_url=f"{settings.APP_BASE_URL}/plans?checkout=cancelled",
        payment_method_types=["card"],
        subscription_data={
            "metadata": {"user_id": str(current_user.id), "plan_id": plan.id},
        },
    )

    return CheckoutResponse(url=session.url)


@router.post("/cancel")
async def cancel_subscription(
    current_user: User = Depends(_get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Cancela ao fim do período (cancel_at_period_end=True)."""
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(503, "Pagamentos não configurados")

    from sqlalchemy import select as sa_select
    from models.subscription import Subscription
    from sqlalchemy import update as sa_update

    res = await db.execute(
        sa_select(Subscription).where(
            Subscription.user_id == current_user.id,
            Subscription.status.in_(["active", "trialing"]),
        ).order_by(Subscription.created_at.desc())
    )
    sub = res.scalar_one_or_none()
    if sub is None:
        raise HTTPException(404, "Assinatura ativa não encontrada")

    stripe.api_key = settings.STRIPE_SECRET_KEY
    stripe.Subscription.modify(sub.stripe_subscription_id, cancel_at_period_end=True)

    await db.execute(
        sa_update(Subscription)
        .where(Subscription.id == sub.id)
        .values(cancel_at_period_end=True)
    )
    await db.commit()
    return {"ok": True, "message": "Assinatura será cancelada ao fim do período."}


@router.post("/reactivate")
async def reactivate_subscription(
    current_user: User = Depends(_get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Desfaz cancel_at_period_end."""
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(503, "Pagamentos não configurados")

    from sqlalchemy import select as sa_select
    from models.subscription import Subscription
    from sqlalchemy import update as sa_update

    res = await db.execute(
        sa_select(Subscription).where(
            Subscription.user_id == current_user.id,
            Subscription.status.in_(["active", "trialing"]),
            Subscription.cancel_at_period_end.is_(True),
        ).order_by(Subscription.created_at.desc())
    )
    sub = res.scalar_one_or_none()
    if sub is None:
        raise HTTPException(404, "Nenhuma assinatura pendente de cancelamento")

    stripe.api_key = settings.STRIPE_SECRET_KEY
    stripe.Subscription.modify(sub.stripe_subscription_id, cancel_at_period_end=False)

    await db.execute(
        sa_update(Subscription)
        .where(Subscription.id == sub.id)
        .values(cancel_at_period_end=False)
    )
    await db.commit()
    return {"ok": True, "message": "Cancelamento desfeito. Assinatura continua ativa."}


@router.get("/invoices")
async def list_invoices(
    current_user: User = Depends(_get_current_user),
) -> list:
    """Retorna últimas 10 faturas do cliente no Stripe."""
    if not settings.STRIPE_SECRET_KEY or not current_user.stripe_customer_id:
        return []

    stripe.api_key = settings.STRIPE_SECRET_KEY
    try:
        invoices = stripe.Invoice.list(
            customer=current_user.stripe_customer_id,
            limit=10,
        )
        return [
            {
                "id": inv.id,
                "number": inv.number,
                "amount_paid": inv.amount_paid,
                "currency": inv.currency,
                "status": inv.status,
                "period_start": inv.period_start,
                "period_end": inv.period_end,
                "hosted_invoice_url": inv.hosted_invoice_url,
                "invoice_pdf": inv.invoice_pdf,
            }
            for inv in invoices.auto_paging_iter()
        ]
    except Exception:
        return []
