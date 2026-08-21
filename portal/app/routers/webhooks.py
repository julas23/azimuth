"""
POST /webhooks/stripe — recebe e processa eventos Stripe.

A assinatura HMAC é validada antes de qualquer processamento.
Idempotência garantida pela tabela webhook_events.
"""
import logging

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.bandwidth import WebhookEvent
from services import provisioner

router = APIRouter(prefix="/webhooks", tags=["webhooks"])
log = logging.getLogger("webhooks")

_HANDLED = {
    "checkout.session.completed",
    "invoice.paid",
    "customer.subscription.deleted",
    "invoice.payment_failed",
}


@router.post("/stripe", status_code=200)
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")

    if settings.STRIPE_WEBHOOK_SECRET:
        stripe.api_key = settings.STRIPE_SECRET_KEY
        try:
            event = stripe.Webhook.construct_event(
                payload, sig, settings.STRIPE_WEBHOOK_SECRET
            )
        except stripe.error.SignatureVerificationError:
            raise HTTPException(status_code=400, detail="Invalid signature")
    else:
        # Dev: aceita sem validar (nunca em produção)
        import json
        event = json.loads(payload)

    event_id = event["id"]
    event_type = event["type"]

    # Idempotência
    existing = await db.get(WebhookEvent, event_id)
    if existing is not None:
        return {"status": "already_processed"}

    # Registra antes de processar para evitar reprocessamento em falha parcial
    db.add(WebhookEvent(stripe_event_id=event_id, event_type=event_type, status="processing"))
    await db.flush()

    if event_type in _HANDLED:
        try:
            if event_type == "checkout.session.completed":
                await provisioner.handle_checkout_completed(event["data"], db)
            elif event_type == "invoice.paid":
                await provisioner.handle_invoice_paid(event["data"], db)
            elif event_type == "customer.subscription.deleted":
                await provisioner.handle_subscription_deleted(event["data"], db)
            elif event_type == "invoice.payment_failed":
                await provisioner.handle_invoice_payment_failed(event["data"], db)

            await db.execute(
                update(WebhookEvent)
                .where(WebhookEvent.stripe_event_id == event_id)
                .values(status="ok")
            )
        except Exception as exc:
            log.exception("Erro ao processar evento %s (%s): %s", event_type, event_id, exc)
            await db.execute(
                update(WebhookEvent)
                .where(WebhookEvent.stripe_event_id == event_id)
                .values(status="error")
            )
            await db.commit()
            raise HTTPException(status_code=500, detail="Processing error")
    else:
        await db.execute(
            update(WebhookEvent)
            .where(WebhookEvent.stripe_event_id == event_id)
            .values(status="ignored")
        )

    await db.commit()
    return {"status": "ok"}
