// QR credentials are encoded locally and are never sent to an external QR API.
function localQRData(text) {
  const holder = document.createElement('div');
  new QRCode(holder, {text, width: 300, height: 300, correctLevel: QRCode.CorrectLevel.M});
  const canvas = holder.querySelector('canvas');
  if (!canvas) throw new Error('QR canvas is unavailable');
  return canvas.toDataURL('image/png');
}
function showLocalQR(text) {
  const dialog = document.createElement('dialog');
  const image = document.createElement('img');
  image.src = localQRData(text);
  image.alt = 'Connection QR';
  image.style.display = 'block';
  const button = document.createElement('button');
  button.textContent = 'بستن';
  button.onclick = () => dialog.close();
  dialog.append(image, button);
  dialog.addEventListener('close', () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
}
