"""Local, metadata-free rendering for an explicitly enabled whole-document fallback."""
import base64
import io
import tempfile
from pathlib import Path
from PIL import Image, ImageSequence, ImageOps
from .storage import current_path

MAX_PAGES = 50
MAX_BYTES = 20 * 1024 * 1024


def document_images(doc):
    from .processing import run
    from .workspace_tools import pdf_pages
    path = current_path(doc)
    result, total = [], 0
    def append(frame):
        nonlocal total
        image = ImageOps.exif_transpose(frame).convert('RGB')
        image.thumbnail((2000, 2000))
        buffer = io.BytesIO(); image.save(buffer, format='JPEG', quality=90)
        payload = buffer.getvalue(); total += len(payload)
        if total > MAX_BYTES or len(result) >= MAX_PAGES:
            raise ValueError('Vollständiges Dokument überschreitet das KI-Seiten- oder Größenlimit.')
        result.append('data:image/jpeg;base64,' + base64.b64encode(payload).decode('ascii'))
    if doc.mime == 'application/pdf':
        count = pdf_pages(path)
        if count > MAX_PAGES: raise ValueError('Vollständige KI-Auswertung unterstützt höchstens 50 Seiten.')
        with tempfile.TemporaryDirectory(prefix='dms-vision-') as directory:
            for page in range(1, count+1):
                target = Path(directory)/'page'
                run(['pdftoppm', '-f', str(page), '-l', str(page), '-scale-to', '2000', '-singlefile', '-png', str(path), str(target)], 45)
                with Image.open(str(target)+'.png') as frame: append(frame)
    elif doc.mime in {'image/png','image/jpeg','image/tiff'}:
        with Image.open(path) as image:
            for frame in ImageSequence.Iterator(image): append(frame)
    else:
        raise ValueError('Vollständige KI-Auswertung benötigt PDF oder Bilddatei.')
    return result
