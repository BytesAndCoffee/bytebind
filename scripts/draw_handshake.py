"""Render the threat model handshake as a portable PNG using Pillow."""
from pathlib import Path
import textwrap

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
FONT = '/System/Library/Fonts/Supplemental/Arial.ttf'
regular = ImageFont.truetype(FONT, 24)
small = ImageFont.truetype(FONT, 21)
bold = ImageFont.truetype('/System/Library/Fonts/Supplemental/Arial Bold.ttf', 26)
positions = [170, 580, 1030, 1440]
rows = [
    ('phase', '1. Create a challenge'),
    ('arrow', 0, 1, 'Start session or submit transaction'),
    ('note', 'RP: check Origin and request limits. For a transaction, compute Q from the request.'),
    ('arrow', 1, 2, 'Create transaction: audience, profile, Q for tx'),
    ('note', 'Authority: authenticate RP; check audience and profile; bind registered origin; create pending cid, C, S.'),
    ('arrow', 2, 1, 'Return cid, C, Authority URL and relative expiry'),
    ('note', 'RP: store state-cookie hash and deadline. For a transaction, store the original request.'),
    ('arrow', 1, 0, 'Return challenge; set state cookie'),
    ('phase', '2. Attest directly over the tailnet'),
    ('note', 'Client: generate N and compute H1. For a transaction, independently compute Q from the exact sent request.'),
    ('arrow', 0, 2, 'POST /attestation: cid, N, H1; configured Origin'),
    ('note', 'Authority: check Host and Origin before reading state; check pending deadline, bound origin and H1.'),
    ('arrow', 2, 3, 'LocalAPI: status / whois for socket peer'),
    ('arrow', 3, 2, 'Return node identity and tags'),
    ('note', 'Authority: reject shared or unknown peers; check identity agreement and RP device policy; atomically mark attested.'),
    ('arrow', 2, 0, 'Return H2: authenticated encryption of IP and S'),
    ('note', 'Client: authenticate and decrypt H2; compute redemption proof R.'),
    ('phase', '3. Redeem the proof once'),
    ('arrow', 0, 1, 'POST /bytebind/proof: cid, R; state cookie and Origin'),
    ('note', 'RP: check Origin and state cookie; atomically claim the ceremony; check deadline.'),
    ('arrow', 1, 2, 'Redeem: cid, R, audience'),
    ('note', 'Authority: authenticate RP; check scope, deadline and R; atomically consume the attested transaction.'),
    ('arrow', 2, 1, 'Return active grant, audience, claims and relative expiry'),
    ('note', 'RP: check active grant and audience.'),
    ('phase', '4. Enforce route authorization'),
    ('outcome', 'Session profile', 'Set lease cookie and return session result. On each protected request, check lease expiry and every route requirement before running the handler.'),
    ('outcome', 'Transaction-bound profile', 'Replay the stored request with its grant. Check operation and every route requirement; run the handler at most once if authorized. Return its result or deny access.'),
]

layout, y = [], 215
for row in rows:
    if row[0] == 'phase': height = 65
    elif row[0] == 'arrow':
        width = abs(positions[row[1]] - positions[row[2]])
        lines = textwrap.wrap(row[3], width=max(23, int(width / 13)))
        height = 44 + len(lines) * 26
    elif row[0] == 'note':
        lines = textwrap.wrap(row[1], width=113)
        height = 34 + len(lines) * 27
    else:
        lines = textwrap.wrap(row[2], width=108)
        height = 68 + len(lines) * 28
    layout.append((row, y, height))
    y += height + 12
image = Image.new('RGB', (1610, y + 85), '#f8fafc')
draw = ImageDraw.Draw(image)
draw.text((45, 28), 'ByteBind handshake', fill='#17263c', font=bold)
draw.text((45, 70), 'Successful exchange: public HTTPS, private attestation, authenticated RP control', fill='#485a70', font=small)
for x in positions:
    for yy in range(195, y, 16):
        draw.line((x, yy, x, min(yy + 8, y)), fill='#b9c5d4', width=2)
for x, label in zip(positions, ['Client on device D', 'Public RP', 'Private Authority', 'tailscaled']):
    draw.rounded_rectangle((x - 145, 120, x + 145, 186), radius=12, fill='#17263c')
    draw.text((x, 153), label, anchor='mm', font=regular, fill='white')
for row, yy, height in layout:
    kind = row[0]
    if kind == 'phase':
        draw.rounded_rectangle((35, yy, 1575, yy + height), radius=8, fill='#dce6f2')
        draw.text((55, yy + 18), row[1], font=bold, fill='#17263c')
    elif kind == 'arrow':
        start, end = positions[row[1]], positions[row[2]]
        lines = textwrap.wrap(row[3], width=max(23, int(abs(start-end) / 13)))
        center = (start + end) / 2
        for i, line in enumerate(lines):
            bbox = draw.textbbox((center, yy + i * 26), line, anchor='mt', font=small)
            draw.rectangle((bbox[0]-5, bbox[1]-2, bbox[2]+5, bbox[3]+2), fill='#f8fafc')
            draw.text((center, yy + i * 26), line, anchor='mt', font=small, fill='#17263c')
        line_y = yy + len(lines) * 26 + 15
        draw.line((start, line_y, end, line_y), fill='#23618d', width=3)
        direction = 1 if end > start else -1
        draw.polygon([(end, line_y), (end-direction*13, line_y-7), (end-direction*13, line_y+7)], fill='#23618d')
    elif kind == 'note':
        draw.rounded_rectangle((55, yy, 1555, yy+height), radius=8, fill='#fff0d9', outline='#d0a65d', width=1)
        for i, line in enumerate(textwrap.wrap(row[1], width=113)):
            draw.text((75, yy + 14 + i*27), line, font=small, fill='#443722')
    else:
        draw.rounded_rectangle((55, yy, 1555, yy+height), radius=8, fill='#e1efe8', outline='#7ba391', width=1)
        draw.text((75, yy+12), row[1], font=bold, fill='#214d3d')
        for i, line in enumerate(textwrap.wrap(row[2], width=108)):
            draw.text((75, yy+52+i*28), line, font=small, fill='#214d3d')
draw.text((45, y+28), 'Transcript encoding and failure rules: SPEC.md sections 9–13. No automatic replay after a lost result.', font=small, fill='#485a70')
image.save(ROOT / 'docs/diagrams/handshake.png')
