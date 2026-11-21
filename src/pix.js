// Gerador de payload PIX Copia e Cola (EMVCo BR Code — Padrão Banco Central do Brasil)
// Sem bibliotecas externas, 100% compatível com doações de qualquer valor.

export const PIX_DONATION_KEY = '6fb71fd9-9a8c-4df2-b071-6a807521eabf';
export const PIX_MERCHANT_NAME = 'Hevert Pereira';
export const PIX_MERCHANT_CITY = 'Brasil';
export const PIX_TXID = 'AEGISAI';

function emvField(id, value) {
  const str = String(value ?? '');
  const len = String(str.length).padStart(2, '0');
  return `${id}${len}${str}`;
}

export function computeCrc16Ccitt(payload) {
  let crc = 0xffff;
  for (let i = 0; i < payload.length; i++) {
    crc ^= payload.charCodeAt(i) << 8;
    for (let j = 0; j < 8; j++) {
      if ((crc & 0x8000) !== 0) {
        crc = ((crc << 1) ^ 0x1021) & 0xffff;
      } else {
        crc = (crc << 1) & 0xffff;
      }
    }
  }
  return crc.toString(16).toUpperCase().padStart(4, '0');
}

export function buildPixCopyPaste({
  pixKey = PIX_DONATION_KEY,
  merchantName = PIX_MERCHANT_NAME,
  merchantCity = PIX_MERCHANT_CITY,
  txid = PIX_TXID,
} = {}) {
  const merchantAccount = emvField(
    '26',
    emvField('00', 'br.gov.bcb.pix') + emvField('01', pixKey.trim())
  );
  const additionalData = emvField('62', emvField('05', txid));

  // Tag 54 omitida propositalmente para permitir doação de qualquer valor no app do banco
  const body =
    emvField('00', '01') +
    merchantAccount +
    emvField('52', '0000') +
    emvField('53', '986') +
    emvField('58', 'BR') +
    emvField('59', merchantName.slice(0, 25)) +
    emvField('60', merchantCity.slice(0, 15)) +
    additionalData +
    '6304';

  return body + computeCrc16Ccitt(body);
}
