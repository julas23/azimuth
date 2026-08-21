"""
Envio de e-mails transacionais via SMTP assíncrono (aiosmtplib).
"""
import asyncio
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

from config import settings


def is_configured() -> bool:
    return bool(settings.SMTP_HOST and settings.SMTP_USER)


async def send_vpn_credentials(
    to_email: str,
    to_name: str,
    plan_name: str,
    client_ip: str,
    conf_text: str,
    qr_png: bytes,
) -> None:
    if not is_configured():
        # Em dev sem SMTP, apenas loga
        import logging
        logging.getLogger("mailer").warning(
            "SMTP não configurado — e-mail para %s não enviado", to_email
        )
        return

    msg = MIMEMultipart("mixed")
    msg["Subject"] = f"Seus dados de acesso VPN — Plano {plan_name}"
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_email

    body = MIMEText(
        f"Olá {to_name},\n\n"
        f"Sua assinatura do Plano {plan_name} está ativa!\n\n"
        f"Endereço IP atribuído: {client_ip}\n\n"
        f"Anexamos o arquivo de configuração do WireGuard (.conf) e o QR Code.\n\n"
        f"Como instalar:\n"
        f"  • iOS/Android: abra o app WireGuard → '+' → 'Criar a partir de QR code'\n"
        f"  • Windows/macOS/Linux: importe o arquivo .conf no app WireGuard\n\n"
        f"Qualquer dúvida, responda este e-mail.\n\n"
        f"Equipe VPN",
        "plain",
        "utf-8",
    )
    msg.attach(body)

    conf_attach = MIMEApplication(conf_text.encode("utf-8"), Name="vpn.conf")
    conf_attach["Content-Disposition"] = 'attachment; filename="vpn.conf"'
    msg.attach(conf_attach)

    qr_attach = MIMEImage(qr_png, _subtype="png", name="qr.png")
    qr_attach["Content-Disposition"] = 'attachment; filename="qr.png"'
    msg.attach(qr_attach)

    await aiosmtplib.send(
        msg,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER,
        password=settings.SMTP_PASSWORD,
        start_tls=settings.SMTP_TLS,
    )


async def send_quota_alert(to_email: str, to_name: str, plan_name: str, pct: float) -> None:
    if not is_configured():
        import logging
        logging.getLogger("mailer").warning(
            "SMTP não configurado — alerta de quota para %s não enviado (%.0f%%)", to_email, pct
        )
        return

    if pct >= 100:
        subject = f"[VPN] Franquia esgotada — Plano {plan_name}"
        body_text = (
            f"Olá {to_name},\n\n"
            f"Sua franquia de dados do Plano {plan_name} foi totalmente consumida (100%).\n\n"
            f"Sua conexão foi reduzida a velocidade mínima. Para restaurar a velocidade "
            f"completa, aguarde o próximo ciclo de cobrança ou faça upgrade de plano.\n\n"
            f"Equipe VPN"
        )
    else:
        subject = f"[VPN] Aviso: {int(pct)}% da franquia usada — Plano {plan_name}"
        body_text = (
            f"Olá {to_name},\n\n"
            f"Você já utilizou {int(pct)}% da sua franquia de dados do Plano {plan_name}.\n\n"
            f"Fique atento ao consumo para evitar redução de velocidade antes do próximo ciclo.\n\n"
            f"Equipe VPN"
        )

    msg = MIMEText(body_text, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_email

    await aiosmtplib.send(
        msg,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER,
        password=settings.SMTP_PASSWORD,
        start_tls=settings.SMTP_TLS,
    )


async def send_verification_email(to_email: str, to_name: str, verify_url: str) -> None:
    if not is_configured():
        import logging
        logging.getLogger("mailer").warning(
            "SMTP não configurado — link de verificação para %s: %s", to_email, verify_url
        )
        return

    msg = MIMEText(
        f"Olá {to_name},\n\n"
        f"Clique no link abaixo para verificar seu e-mail e ativar sua conta:\n\n"
        f"{verify_url}\n\n"
        f"O link expira em 24 horas.\n\n"
        f"Se você não criou esta conta, ignore este e-mail.\n\n"
        f"Equipe VPN",
        "plain",
        "utf-8",
    )
    msg["Subject"] = "Verifique seu e-mail — VPN Brasil"
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_email

    await aiosmtplib.send(
        msg,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER,
        password=settings.SMTP_PASSWORD,
        start_tls=settings.SMTP_TLS,
    )


async def send_subscription_cancelled(to_email: str, to_name: str, plan_name: str) -> None:
    if not is_configured():
        return

    msg = MIMEText(
        f"Olá {to_name},\n\n"
        f"Sua assinatura do Plano {plan_name} foi cancelada.\n\n"
        f"Seu acesso VPN foi revogado. Se isso foi um engano, "
        f"entre em contato conosco.\n\n"
        f"Equipe VPN",
        "plain",
        "utf-8",
    )
    msg["Subject"] = f"Assinatura {plan_name} cancelada"
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_email

    await aiosmtplib.send(
        msg,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER,
        password=settings.SMTP_PASSWORD,
        start_tls=settings.SMTP_TLS,
    )
