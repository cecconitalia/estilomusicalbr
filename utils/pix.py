import os
import qrcode
from io import BytesIO
import base64
import re

class PixError(Exception):
    pass

def generate_valid_pix(amount, pedido_id):
    def calculate_crc16(data: str) -> str:
        crc = 0xFFFF
        for byte in data.encode('ascii'):
            crc ^= byte << 8
            for _ in range(8):
                crc = (crc << 1) ^ 0x1021 if (crc & 0x8000) else crc << 1
        crc &= 0xFFFF
        return f"{crc:04X}"

    try:
        # Validações
        if not all([
            os.getenv('PIX_KEY'),
            os.getenv('PIX_KEY_TYPE'),
            os.getenv('PIX_MERCHANT_NAME'),
            os.getenv('PIX_MERCHANT_CITY')
        ]):
            raise PixError("Configurações Pix incompletas")

        # Formatação do valor
        amount = float(amount)
        if amount <= 0:
            raise PixError("Valor deve ser positivo")
        amount_str = f"{amount:.2f}"

        # Dados do beneficiário
        pix_key = os.getenv('PIX_KEY')
        merchant_name = os.getenv('PIX_MERCHANT_NAME')
        merchant_city = os.getenv('PIX_MERCHANT_CITY')
        txid = f"PED{pedido_id}"  # TXID único baseado no ID do pedido

        # Construção do payload corrigido seguindo padrão EMV
        payload = [
            ('00', '01'),  # Payload Format Indicator
            ('26', f'0014BR.GOV.BCB.PIX01{len(pix_key):02}{pix_key}'),  # Merchant Account Information
            ('52', '0000'),  # Merchant Category Code
            ('53', '986'),  # Transaction Currency (BRL)
            ('54', amount_str),  # Transaction Amount
            ('58', 'BR'),  # Country Code
            ('59', merchant_name),  # Merchant Name
            ('60', merchant_city),  # Merchant City
            ('62', f'05{len(txid):02}{txid}')  # Additional Data Field (TXID)
        ]

        # Converter para string no formato EMV
        payload_str = ''.join(
            f'{id}{len(value):02}{value}' for id, value in payload
        )
        
        # Adicionar CRC16
        payload_str += '6304'
        crc = calculate_crc16(payload_str)
        full_payload = payload_str + crc

        # Verificação do CRC
        if not full_payload.endswith(crc):
            raise PixError("Erro no cálculo do CRC16")

        # Geração do QR Code
        qr = qrcode.QRCode(
            version=12,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=8,
            border=4
        )
        qr.add_data(full_payload)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        return {
            'qr_code': f"data:image/png;base64,{img_str}",
            'payload': full_payload,
            'key': pix_key,
            'amount': amount_str,
            'merchant': merchant_name,
            'city': merchant_city
        }

    except Exception as e:
        raise PixError(f"Falha na geração: {str(e)}")