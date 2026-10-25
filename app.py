"""
열품타 픽셀 챌린지 · 학급용 공부 인증 게임 웹앱
================================================================
- 학생: 공부 시간 입력(인증 제출) → 관리자 승인 → 코인 → 캐릭터 꾸미기
- 관리자: 주소 끝에 ?admin 을 붙여서 접속  (예: https://내앱.streamlit.app/?admin)

중요한 원칙
- 코인 지급·구매처럼 "돈" 같은 일은 전부 DB 함수(schema.sql)가 처리한다.
  이 파일(app.py)은 DB 함수를 "부르기만" 한다.
- 비밀번호·키는 이 파일에 쓰지 않는다. 전부 Streamlit Secrets 에서 읽는다.
"""

import hashlib
import hmac
import html
import re
import secrets
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st
from supabase import create_client


# ════════════════════════════════════════════════════════════════
# ① 게임 설정 — 규칙을 바꾸고 싶으면 여기만 고치면 된다!
# ════════════════════════════════════════════════════════════════

# 보상 규칙 (관리자가 "승인"한 시간 기준으로 계산)
#  - attendance : 하루 인증이 승인되면 받는 출석 코인
#  - milestones : 그날 공부 시간이 minutes(분) 이상이면 coins 추가 (달성한 것 모두 합산)
REWARD_RULES = {
    "attendance": 10,
    "milestones": [
        {"minutes": 60, "coins": 10},    # 1시간 이상 +10
        {"minutes": 120, "coins": 10},   # 2시간 이상 +10
        {"minutes": 180, "coins": 15},   # 3시간 이상 +15
    ],
}

# 아래 두 값은 DB(schema.sql 의 submit_study 함수)에도 똑같이 들어 있다.
# 바꾸려면 두 곳을 같이 바꿔야 한다. (DB가 최종 검사를 하기 때문)
MAX_DAILY_MINUTES = 16 * 60      # 하루 최대 16시간
SUBMIT_WINDOW_DAYS = 3           # 오늘 포함 최근 3일까지 제출 가능

# 상점 기본 아이템 (id 는 영어 소문자/숫자/_ 만, 한 번 정하면 바꾸지 않기)
# ※ 학생들이 그린 아이템은 여기가 아니라 관리자 화면 [🎨 아이템 등록] 에서 추가한다.
CATEGORIES = ["머리", "모자", "얼굴", "볼", "옷", "장식"]   # 같은 부위는 하나만 착용
RARITIES = ["일반", "희귀", "에픽"]
ITEMS = [
    {"id": "cap_blue",   "name": "파란 모자",        "category": "모자", "price": 30,  "rarity": "일반"},
    {"id": "glasses",    "name": "동그란 안경",      "category": "얼굴", "price": 40,  "rarity": "일반"},
    {"id": "hoodie",     "name": "민트 후드",        "category": "옷",   "price": 60,  "rarity": "희귀"},
    {"id": "star",       "name": "반짝 별",          "category": "장식", "price": 80,  "rarity": "희귀"},
    {"id": "crown",      "name": "픽셀 왕관",        "category": "모자", "price": 150, "rarity": "에픽"},
    {"id": "book",       "name": "공부 책",          "category": "장식", "price": 25,  "rarity": "일반"},
    {"id": "blush_pink", "name": "발그레 볼터치",    "category": "볼",   "price": 20,  "rarity": "일반"},
    {"id": "dress_pink", "name": "핑크 원피스",      "category": "옷",   "price": 50,  "rarity": "희귀"},
    {"id": "hair_long",  "name": "핀 꽂은 긴 머리",  "category": "머리", "price": 70,  "rarity": "희귀"},
]
BUILTIN_BY_ID = {item["id"]: item for item in ITEMS}

# 디자인 등록권: 학생이 사서 그림을 보내면, 관리자가 [🎨 아이템 등록] 에서 상점에 올림
DESIGN_TICKET_PRICE = 50     # 등록권 가격 (코인)
MAX_UNUSED_TICKETS = 3       # 아직 안 쓴 등록권은 최대 몇 장까지 가지고 있을 수 있는지

# 계정 보안
PIN_ITERATIONS = 600_000     # PIN 해시 반복 횟수 (OWASP 권장: PBKDF2-SHA256 60만 회)
LOGIN_MAX_FAIL = 5           # 연속 실패 허용 횟수
LOGIN_LOCK_MINUTES = 10      # 잠금 시간(분)
NICKNAME_RE = re.compile(r"[가-힣A-Za-z0-9_]{2,12}")

KST = timezone(timedelta(hours=9))   # 한국 시간 (서머타임 없음)


# ════════════════════════════════════════════════════════════════
# ② 기본 도우미 함수
# ════════════════════════════════════════════════════════════════

def get_secret(key: str) -> str:
    """Streamlit Secrets 에서 값을 읽는다. 없으면 빈 문자열."""
    try:
        return str(st.secrets.get(key, "") or "")
    except Exception:
        return ""


@st.cache_resource
def _make_client(url: str, key: str):
    return create_client(url, key)


def get_db():
    url = get_secret("SUPABASE_URL").strip()
    # 새 방식 secret key(sb_secret_...) 또는 예전 방식 service_role key 둘 다 지원
    key = (get_secret("SUPABASE_SECRET_KEY") or get_secret("SUPABASE_SERVICE_ROLE_KEY")).strip()
    if not url or not key:
        return None   # 없을 때는 기억(캐시)하지 않음 → Secrets 넣으면 바로 반영
    return _make_client(url, key)   # URL/키가 바뀌면 새로 연결


class DBError(Exception):
    pass


def rpc(fn: str, **params):
    """DB 함수를 호출한다. 실패하면 DBError."""
    try:
        return get_db().rpc(fn, params).execute().data
    except Exception as exc:  # 네트워크 오류, 권한 오류 등
        print(f"[DB ERROR] {fn}: {exc!r}")  # 서버 로그에만 남김 (학생 화면엔 안 보임)
        raise DBError(fn) from exc


def safe_rpc(fn: str, fail_msg: str = "서버와 연결이 잠깐 불안정해. 잠시 후 다시 시도해 줘.", **params):
    """DB 함수를 호출하고, 실패하면 화면에 안내 메시지를 띄운 뒤 None 을 돌려준다."""
    try:
        return rpc(fn, **params)
    except DBError:
        st.error("⚠️ " + fail_msg)
        return None


def kst_today():
    return datetime.now(KST).date()


def to_kst(ts) -> str:
    """DB 시각(UTC 문자열)을 한국 시간 'YYYY-MM-DD HH:MM' 으로"""
    if not ts:
        return ""
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(KST).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return str(ts)[:16]


def fmt_minutes(minutes) -> str:
    minutes = int(minutes or 0)
    h, m = divmod(minutes, 60)
    if h and m:
        return f"{h}시간 {m}분"
    if h:
        return f"{h}시간"
    return f"{m}분"


def calc_rewards(minutes: int):
    """승인 시 예상 보상 (화면 표시용). 실제 지급은 DB 함수가 같은 규칙으로 계산한다."""
    attendance = REWARD_RULES["attendance"]
    bonus_lines = [(r["minutes"], r["coins"]) for r in REWARD_RULES["milestones"] if minutes >= r["minutes"]]
    bonus = sum(c for _, c in bonus_lines)
    return {"attendance": attendance, "bonus": bonus, "bonus_lines": bonus_lines, "total": attendance + bonus}


def hash_pin(pin: str, salt: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), iterations).hex()


def weak_pin(pin: str) -> bool:
    """000000, 111111, 123456, 654321 같은 너무 쉬운 PIN 차단"""
    if len(set(pin)) == 1:
        return True
    digits = [int(c) for c in pin]
    steps = {b - a for a, b in zip(digits, digits[1:])}
    return steps in ({1}, {-1})


def flash(kind: str, msg: str):
    """다음 화면 새로고침 뒤에 보여 줄 메시지 저장"""
    st.session_state.setdefault("flash", []).append((kind, msg))


def show_flash():
    # 메시지가 있든 없든 항상 같은 자리(container)를 만들어 둔다.
    # (자리가 생겼다 사라지면 Streamlit 이 탭 위치를 헷갈려 첫 탭으로 돌아가 버림)
    box = st.container()
    for kind, msg in st.session_state.pop("flash", []):
        getattr(box, kind)(msg)


def esc(text) -> str:
    """HTML 에 넣기 전에 특수문자를 안전하게 바꿈 (화면 조작 공격 방지)"""
    return html.escape(str(text), quote=True)


STATUS_LABEL = {"pending": "⏳ 검토 중", "approved": "✅ 승인", "rejected": "↩️ 반려"}


# ════════════════════════════════════════════════════════════════
# ③ 픽셀 캐릭터 (16 x 19 칸 도트를 SVG 그림으로 그림)
#    '.' = 투명,  나머지 글자 = PALETTE 의 색
# ════════════════════════════════════════════════════════════════

PALETTE = {
    "h": "#5b3a29", "s": "#ffd7b5", "e": "#2b2140", "r": "#ff9aa2", "m": "#c2185b",
    "t": "#6c8cff", "p": "#3d3a5c", "b": "#1e1b2e", "c": "#3b82f6", "w": "#ffffff",
    "y": "#ffc93c", "j": "#e63946", "g": "#2b2140", "k": "#7ee0c3", "K": "#4fb894",
    "n": "#8b5a2b", "u": "#cfe8ff",
    # 학생 디자인 (볼터치/원피스/긴 머리)
    "P": "#ff6bfa", "L": "#faadff", "Y": "#ffff00", "R": "#ff0055",
}

BASE_SPRITE = [
    "................",
    "................",
    "......hhhh......",
    "....hhhhhhhh....",
    "...hhhhhhhhhh...",
    "...hhsssssshh...",
    "...hssssssssh...",
    "...sssessesss...",
    "...sssessesss...",
    "...rssssssssr...",
    "....sssmmsss....",
    ".....ssssss.....",
    "....tttttttt....",
    "...tttttttttt...",
    "..stttttttttts..",
    "..s.tttttttt.s..",
    "....pppppppp....",
    "....ppp..ppp....",
    "...bbbb..bbbb...",
]

# 아이템별 덧그림 {줄 번호: 16칸 문자열}
ITEM_SPRITES = {
    "cap_blue": {
        2: ".....cccccc.....",
        3: "....cccwcccc....",
        4: "...ccccccccccccc",
    },
    "crown": {
        0: "....y..yy..y....",
        1: "....yy.yy.yy....",
        2: "....yyyyyyyy....",
        3: "....yjyyyyjy....",
    },
    "glasses": {
        7: "....gg.gg.gg....",
        8: ".....guggugg....",
    },
    "hoodie": {
        3: "...k........k...",
        4: "..k..........k..",
        5: "..k..........k..",
        6: "..k..........k..",
        7: "..k..........k..",
        8: "..k..........k..",
        9: "..k..........k..",
        10: "..kk........kk..",
        11: "...kk......kk...",
        12: "....kkwkkwkk....",
        13: "...kkkwkkwkkk...",
        14: "..skkkkkkkkkks..",
        15: "..s.kKKKKKKk.s..",
    },
    "star": {
        0: "..............y.",
        1: ".............yyy",
        2: "..............y.",
    },
    "book": {
        13: "nnn.............",
        14: "nwn.............",
        15: "nwn.............",
        16: "nnn.............",
    },
    "blush_pink": {
        9: "...rrr....rrr...",
    },
    "dress_pink": {
        12: "....PPPssPPP....",
        13: "...PPPPYYPPPP...",
        14: "...PPPPPPPPPP...",
        15: "....PPPPPPPP....",
        16: "...LLLLLLLLLL...",
        17: "...LLLLLLLLLL...",
    },
    "hair_long": {
        2: "......hhhh......",
        3: "....hhhhhhhh....",
        4: "...hhhhhhhhhh...",
        5: "...hhhhhhhhhh...",
        6: "...hhhhhhhhhh...",
        7: "...hh......hh...",
        8: "..hR........h...",
        9: "..hh........h...",
        10: "..hh............",
        11: "..hh............",
        12: "..hh............",
        13: "..h.............",
    },
}

# 겹쳐 그리는 순서 (뒤쪽 → 앞쪽): 모자가 머리 위, 안경이 머리카락 위에 오도록
LAYER_ORDER = ["옷", "머리", "볼", "얼굴", "모자", "장식"]
HEX_RE = re.compile(r"#[0-9a-f]{6}")


def builtin_grid(item_id: str):
    """기본 아이템 글자 그림 → 19x16 색 격자 (#rrggbb 또는 None)"""
    grid = [[None] * 16 for _ in range(len(BASE_SPRITE))]
    for row_idx, row in ITEM_SPRITES.get(item_id, {}).items():
        for col_idx, ch in enumerate(row):
            if ch in PALETTE:
                grid[row_idx][col_idx] = PALETTE[ch]
    return grid


@st.cache_data(ttl=30, show_spinner=False)
def load_custom_items():
    """학생 디자인 아이템 (숨긴 것 포함). DB 오류 시 빈 목록."""
    try:
        rows = rpc("custom_items_list", p_include_inactive=True) or []
    except DBError:
        return []
    return [{"id": r["id"], "name": r["name"], "category": r["category"], "price": int(r["price"]),
             "rarity": r["rarity"], "creator": r["creator"], "active": bool(r["active"]),
             "owners": r.get("owners", 0), "sprite": r["sprite"], "custom": True} for r in rows]


def catalog(include_hidden: bool = False):
    """상점 전체 목록 = 기본 아이템 + 학생 디자인 아이템"""
    items = [dict(i, custom=False, active=True, creator=None) for i in ITEMS]
    items += [c for c in load_custom_items() if include_hidden or c["active"]]
    return items


def item_info(item_id: str):
    if item_id in BUILTIN_BY_ID:
        return BUILTIN_BY_ID[item_id]
    return next((c for c in load_custom_items() if c["id"] == item_id), None)


def item_grid(item_id: str):
    if item_id in BUILTIN_BY_ID:
        return builtin_grid(item_id)
    info = item_info(item_id)
    return info["sprite"] if info else None


def layers_rects(layers, with_base: bool = True) -> str:
    """색 격자 여러 장을 순서대로 겹쳐 <rect> 조각(1칸=1단위)으로 만든다."""
    h = len(BASE_SPRITE)
    grid = [[PALETTE.get(ch) for ch in row] for row in BASE_SPRITE] if with_base else [[None] * 16 for _ in range(h)]
    for layer in layers:
        if not layer:
            continue
        for y, row in enumerate(layer[:h]):
            for x, color in enumerate(row[:16]):
                if color:
                    grid[y][x] = color
    rects = []
    for y, row in enumerate(grid):
        for x, color in enumerate(row):
            if color and HEX_RE.fullmatch(str(color).lower()):   # 이상한 값은 그리지 않음 (보안)
                rects.append(f'<rect x="{x}" y="{y}" width="1" height="1" fill="{color}"/>')
    return "".join(rects)


def svg_from_layers(layers, px: int = 10, with_base: bool = True) -> str:
    h = len(BASE_SPRITE)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 {h}" width="{16 * px}" '
            f'height="{h * px}" shape-rendering="crispEdges" role="img" aria-label="픽셀 캐릭터">'
            + layers_rects(layers, with_base) + "</svg>")


def equipped_layers(equipped: dict, extra: dict = None):
    layers = []
    for category in LAYER_ORDER:
        if extra and category in extra:
            layers.append(extra[category])
        elif equipped.get(category):
            layers.append(item_grid(equipped[category]))
    return layers


def avatar_svg(equipped: dict, px: int = 10, extra: dict = None) -> str:
    """equipped = {부위: 아이템id}. extra = {부위: 색 격자} (등록 전 미리보기용)"""
    return svg_from_layers(equipped_layers(equipped, extra), px)


def png_to_grid(data: bytes, white_is_empty: bool = True, remove_base: bool = False):
    """학생이 그린 PNG → 19x16 색 격자. (격자, 안내 메시지 목록) 을 돌려준다. 실패하면 격자=None"""
    from io import BytesIO
    from PIL import Image  # Streamlit 에 포함된 패키지

    try:
        img = Image.open(BytesIO(data))
        img.load()
    except Exception:
        return None, ["그림 파일을 열 수 없어요. PNG/JPG 파일인지 확인해 주세요."]
    w, h = img.size
    if w < 16 or h < 19 or w * h > 4000 * 4000:
        return None, [f"그림 크기가 이상해요 ({w}×{h}). 도안(320×380)에 그려 주세요."]
    ratio = (w / 16) / (h / 19)
    if abs(ratio - 1) > 0.06:
        return None, [f"가로:세로 비율이 16:19 가 아니에요 ({w}×{h}). 도안 크기 그대로 저장해 주세요."]
    img = img.convert("RGBA")
    cw, ch = w / 16, h / 19
    base = [[PALETTE.get(c) for c in row] for row in BASE_SPRITE]
    grid, notes = [], []
    for y in range(19):
        row = []
        for x in range(16):
            # 칸 가운데 60% 영역에서 가장 많이 쓰인 색을 고름 (경계선 번짐 무시)
            x0, x1 = int(x * cw + cw * 0.2), max(int(x * cw + cw * 0.8), int(x * cw + cw * 0.2) + 1)
            y0, y1 = int(y * ch + ch * 0.2), max(int(y * ch + ch * 0.8), int(y * ch + ch * 0.2) + 1)
            step = max(1, int(min(cw, ch) // 8))
            counts = {}
            for yy in range(y0, y1, step):
                for xx in range(x0, x1, step):
                    r, g, b, a = img.getpixel((xx, yy))
                    if a < 128 or (white_is_empty and min(r, g, b) > 238):
                        key = None
                    else:
                        key = f"#{r:02x}{g:02x}{b:02x}"
                    counts[key] = counts.get(key, 0) + 1
            total = sum(counts.values())
            empty = counts.pop(None, 0)
            color = max(counts, key=counts.get) if counts and empty * 2 < total else None
            if color and remove_base and base[y][x]:
                br, bg, bb = (int(base[y][x][i:i + 2], 16) for i in (1, 3, 5))
                cr, cg, cb = (int(color[i:i + 2], 16) for i in (1, 3, 5))
                if abs(br - cr) + abs(bg - cg) + abs(bb - cb) < 30:
                    color = None
            row.append(color)
        grid.append(row)
    filled = sum(1 for r in grid for c in r if c)
    if filled == 0:
        return None, ["칠해진 칸이 하나도 없어요. 배경만 있는 그림인지 확인해 주세요."]
    notes.append(f"칠해진 칸 {filled}개 · 사용한 색 {len({c for r in grid for c in r if c})}가지")
    if filled > 150:
        notes.append("칠해진 칸이 아주 많아요. 기본 캐릭터까지 같이 저장된 그림이면 "
                     "'기본 캐릭터 부분 지우기'를 켜 보세요.")
    return grid, notes


@st.cache_data(show_spinner=False)
def template_png() -> bytes:
    """학생용 도안: 기본 캐릭터가 그려진 320x380 투명 PNG"""
    from io import BytesIO
    from PIL import Image
    img = Image.new("RGBA", (16, len(BASE_SPRITE)), (0, 0, 0, 0))
    for y, row in enumerate(BASE_SPRITE):
        for x, c in enumerate(row):
            if c in PALETTE:
                hx = PALETTE[c]
                img.putpixel((x, y), (int(hx[1:3], 16), int(hx[3:5], 16), int(hx[5:7], 16), 255))
    buf = BytesIO()
    img.resize((320, 380), Image.NEAREST).save(buf, format="PNG")
    return buf.getvalue()


# ════════════════════════════════════════════════════════════════
# ③-2 우리 반 광장 (캐릭터들이 한 화면에 모이는 곳)
# ════════════════════════════════════════════════════════════════

PLAZA_W = 540            # 그림 가로 크기 (화면 폭에 맞춰 자동으로 늘었다 줄었다 함)
PLAZA_FLOOR = 215        # 이 높이부터 바닥 (캐릭터가 서는 곳)
PLAZA_ROW_H = 100        # 캐릭터 줄 간격
PLAZA_COLS = 6           # 한 줄 최대 인원
CHAR_SCALE = 3           # 캐릭터 크기 (16x19칸 x 3배)
RANK_COLORS = {1: ("#ffc93c", "#b8860b"), 2: ("#d9dde6", "#8a93a6"), 3: ("#e3a06a", "#a0582a")}
PLAZA_BACKGROUNDS = {"classroom": "🏫 교실", "field": "🌳 운동장", "night": "🌙 밤하늘", "custom": "🖼️ 내가 올린 그림"}


def plaza_bg_svg(kind: str, image: str, w: int, h: int) -> str:
    """배경 그림 (기본 3종은 코드로 그린 도트 배경, custom 은 관리자가 올린 이미지)"""
    f = PLAZA_FLOOR
    if kind == "custom" and image and re.fullmatch(r"data:image/(png|jpeg);base64,[A-Za-z0-9+/=]+", image):
        return f'<image href="{image}" x="0" y="0" width="{w}" height="{h}" preserveAspectRatio="xMidYMid slice"/>'
    if kind == "field":
        parts = [f'<rect width="{w}" height="{h}" fill="#9fd8ff"/>',
                 f'<rect y="{f - 70}" width="{w}" height="70" fill="#b9e4ff"/>']
        for cx, cy in ((70, 40), (300, 70), (460, 30)):          # 구름
            parts += [f'<rect x="{cx}" y="{cy}" width="70" height="16" fill="#ffffff"/>',
                      f'<rect x="{cx + 14}" y="{cy - 12}" width="38" height="14" fill="#ffffff"/>']
        parts += [f'<rect x="{w - 140}" y="{f - 70}" width="110" height="70" fill="#f4e3c1"/>',   # 학교 건물
                  f'<rect x="{w - 140}" y="{f - 82}" width="110" height="12" fill="#c0504d"/>']
        parts += [f'<rect x="{w - 130 + i * 26}" y="{f - 58}" width="14" height="14" fill="#7fb6e0"/>' for i in range(4)]
        parts.append(f'<rect y="{f}" width="{w}" height="{h - f}" fill="#7cc66b"/>')
        parts += [f'<rect x="{x}" y="{f}" width="30" height="{h - f}" fill="#72bb61"/>' for x in range(0, w, 60)]
        parts.append(f'<rect y="{f + 6}" width="{w}" height="6" fill="#e08a5b"/>')
        return "".join(parts)
    if kind == "night":
        parts = [f'<rect width="{w}" height="{h}" fill="#1b1f3b"/>',
                 f'<rect y="{f - 60}" width="{w}" height="60" fill="#262b52"/>']
        for i in range(40):                                       # 별 (항상 같은 자리)
            x, y = (i * 137) % w, (i * 53) % (f - 40)
            sz = 3 if i % 5 == 0 else 2
            parts.append(f'<rect x="{x}" y="{y}" width="{sz}" height="{sz}" fill="#fff6c9"/>')
        parts += ['<circle cx="458" cy="52" r="20" fill="#ffe9a3"/>',
                  '<circle cx="468" cy="45" r="17" fill="#1b1f3b"/>']   # 초승달
        parts.append(f'<rect y="{f}" width="{w}" height="{h - f}" fill="#2f3d2e"/>')
        parts += [f'<rect x="{x}" y="{f}" width="20" height="4" fill="#3d5239"/>' for x in range(0, w, 40)]
        return "".join(parts)
    # classroom (기본)
    parts = [f'<rect width="{w}" height="{h}" fill="#ffecd0"/>',
             f'<rect x="{w * 0.18:.0f}" y="24" width="{w * 0.64:.0f}" height="110" fill="#2e5a46" stroke="#7a5230" stroke-width="7"/>',
             f'<text x="{w / 2:.0f}" y="88" text-anchor="middle" font-size="22" fill="#f0f0e6" '
             f'font-family="Galmuri11, sans-serif">오늘도 열공!</text>',
             f'<rect x="{w * 0.18:.0f}" y="134" width="{w * 0.64:.0f}" height="6" fill="#7a5230"/>',
             f'<rect y="{f - 10}" width="{w}" height="10" fill="#c99566"/>',
             f'<rect y="{f}" width="{w}" height="{h - f}" fill="#d6aa78"/>']
    parts += [f'<rect x="{x}" y="{f}" width="2" height="{h - f}" fill="#c4966a"/>' for x in range(0, w, 30)]
    return "".join(parts)


def _label_width(text: str, size: int = 11) -> float:
    return sum(size if ord(ch) > 0x1100 else size * 0.6 for ch in text) + 12


def plaza_svg(rows, me_nickname: str, bg_kind: str, bg_image: str) -> str:
    """rows = [{player_id, nickname, total_minutes, equipped}] → 광장 SVG"""
    n = len(rows)
    # 등수: 승인된 시간이 많은 순 (같은 시간이면 같은 등수, 0분은 등수 없음 🌱)
    ranked = sorted(rows, key=lambda r: -int(r["total_minutes"]))
    rank_of, prev, rank = {}, None, 0
    for i, r in enumerate(ranked, start=1):
        if r["total_minutes"] != prev:
            rank, prev = i, r["total_minutes"]
        rank_of[r["player_id"]] = rank if r["total_minutes"] > 0 else None

    # 자리: 학생마다 고정된 '무작위' 칸 (새로고침해도 같은 자리)
    def h(pid, salt=""):
        return int(hashlib.sha256((str(pid) + salt).encode()).hexdigest(), 16)
    order = sorted(rows, key=lambda r: h(r["player_id"]))
    cols = max(1, min(PLAZA_COLS, n))
    nrows = max(1, -(-n // cols))
    W = PLAZA_W
    H = PLAZA_FLOOR + nrows * PLAZA_ROW_H + 20
    cell_w = W / cols
    cw, ch = 16 * CHAR_SCALE, len(BASE_SPRITE) * CHAR_SCALE
    placed = []
    for idx, r in enumerate(order):
        row_i, col_i = divmod(idx, cols)
        jx = (h(r["player_id"], "x") % 1000 / 1000 - 0.5) * cell_w * 0.22   # 좌우로 살짝만 흩어지게 (이름표 겹침 방지)
        jy = (h(r["player_id"], "y") % 1000 / 1000 - 0.5) * 24
        cx = cell_w * (col_i + 0.5) + jx
        top = PLAZA_FLOOR + row_i * PLAZA_ROW_H + 4 + jy
        placed.append((top, cx, r))

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H:.0f}" width="100%" '
           f'role="img" aria-label="우리 반 광장" style="display:block;border-radius:6px">',
           plaza_bg_svg(bg_kind, bg_image, W, int(H))]
    for top, cx, r in sorted(placed, key=lambda t: t[0]):          # 뒤에 있는 사람부터 그림
        x0 = cx - cw / 2
        rk = rank_of[r["player_id"]]
        out.append(f'<ellipse cx="{cx:.1f}" cy="{top + ch:.1f}" rx="{cw * 0.42:.1f}" ry="5" fill="#000" opacity=".18"/>')
        out.append(f'<g transform="translate({x0:.1f},{top:.1f}) scale({CHAR_SCALE})" shape-rendering="crispEdges">'
                   + layers_rects(equipped_layers(r["equipped"] or {})) + "</g>")
        if rk in RANK_COLORS:                                        # 1~3등 작은 왕관
            fill, dark = RANK_COLORS[rk]
            kx, ky = cx - 9, top - 13          # 모자·왕관 아이템과 안 겹치게 머리 위로 띄움
            crown = ["x.x.x", "xxxxx", "xjxjx"]
            for yy, line in enumerate(crown):
                for xx, c in enumerate(line):
                    if c != ".":
                        col = "#e63946" if c == "j" else fill
                        out.append(f'<rect x="{kx + xx * 3.6:.1f}" y="{ky + yy * 3.6:.1f}" width="3.6" height="3.6" fill="{col}"/>')
        text = (f"{rk}등 " if rk else "🌱 ") + r["nickname"]
        lw = _label_width(text)
        ly = top + ch + 3
        is_me = r["nickname"] == me_nickname
        if rk in RANK_COLORS:
            fill, stroke, sw = RANK_COLORS[rk][0], RANK_COLORS[rk][1], 1.5
        else:
            fill, stroke, sw = "#ffffff", "#2b2140", 1
        if is_me:
            stroke, sw = "#7c5cff", 2.5
        out.append(f'<rect x="{cx - lw / 2:.1f}" y="{ly:.1f}" width="{lw:.1f}" height="17" rx="4" '
                   f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>')
        out.append(f'<text x="{cx:.1f}" y="{ly + 12.5:.1f}" text-anchor="middle" font-size="11" fill="#2b2140" '
                   f'font-family="Galmuri11, sans-serif" font-weight="700">{esc(text)}</text>')
    out.append("</svg>")
    return "".join(out)


@st.cache_data(ttl=30, show_spinner=False)
def cached_plaza():
    return rpc("plaza_data") or [], rpc("get_plaza_bg") or {}


def image_to_data_uri(data: bytes):
    """관리자가 올린 배경 그림 → 크기 줄이고 data URI 로 (DB에 저장하기 위해)"""
    import base64
    from io import BytesIO
    from PIL import Image
    try:
        img = Image.open(BytesIO(data))
        img.load()
    except Exception:
        return None, "그림 파일을 열 수 없어요. PNG/JPG 파일인지 확인해 주세요."
    img.thumbnail((1080, 1080))
    has_alpha = img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info)
    buf = BytesIO()
    if has_alpha:
        img.convert("RGBA").save(buf, format="PNG", optimize=True)
        mime = "png"
    else:
        img.convert("RGB").save(buf, format="JPEG", quality=85)
        mime = "jpeg"
    if len(buf.getvalue()) > 1_400_000:          # 그래도 크면 JPEG 로 더 줄이기
        buf = BytesIO()
        img.convert("RGB").save(buf, format="JPEG", quality=70)
        mime = "jpeg"
    uri = f"data:image/{mime};base64," + base64.b64encode(buf.getvalue()).decode()
    if len(uri) > 2_000_000:
        return None, "그림이 너무 커요. 더 작은 그림으로 올려 주세요."
    return uri, None


# ════════════════════════════════════════════════════════════════
# ④ 화면 꾸미기 (픽셀 게임 스타일 CSS)
# ════════════════════════════════════════════════════════════════

def inject_css():
    st.markdown(
        """
<style>
@import url('https://cdn.jsdelivr.net/npm/galmuri@2.40.3/dist/galmuri.css');
:root { --ink:#2b2140; --paper:#fff8ec; --violet:#7c5cff; --mint:#7ee0c3; --gold:#ffc93c; --pink:#ff9aa2; }
h1, h2, h3, h4, .px-font, .stTabs button p, .stButton button p, .stFormSubmitButton button p,
[data-testid="stMetricValue"] { font-family: 'Galmuri11', 'Galmuri9', 'Pretendard', sans-serif !important; }
.block-container { padding-top: 3.2rem; padding-bottom: 4rem; max-width: 760px; }
.px-title { font-family:'Galmuri11',sans-serif; font-size: 1.7rem; color: var(--ink); text-align:center;
            margin: 0 0 .2rem 0; text-shadow: 2px 2px 0 #ffe08a; }
.px-sub { text-align:center; color:#6b6385; font-size:.9rem; margin-bottom:1rem; }
.px-card { background:#fff; border:3px solid var(--ink); border-radius:6px; box-shadow:4px 4px 0 var(--ink);
           padding:14px 16px; margin: 6px 0 14px 0; color: var(--ink); }
.px-card.violet { background:#f1e9ff; } .px-card.mint { background:#e6fbf4; } .px-card.gold { background:#fff3cf; }
.px-row { display:flex; gap:16px; align-items:center; flex-wrap:wrap; }
.px-avatar { background: repeating-conic-gradient(#f4efff 0 25%, #ffffff 0 50%) 50% / 20px 20px;
             border:3px solid var(--ink); border-radius:6px; padding:8px; display:inline-block; line-height:0; }
.px-stat { font-family:'Galmuri11',sans-serif; font-size:1.25rem; }
.px-label { font-size:.8rem; color:#6b6385; }
.px-badge { display:inline-block; font-family:'Galmuri11',sans-serif; font-size:.78rem; padding:2px 8px;
            border:2px solid var(--ink); border-radius:4px; background:#fff; margin:2px 4px 2px 0; }
.px-badge.pending { background:#fff3cf; } .px-badge.approved { background:#d9f7ea; } .px-badge.rejected { background:#ffe1e4; }
.px-bar { height:26px; border:3px solid var(--ink); background:#fff; border-radius:4px; overflow:hidden; }
.px-bar > div { height:100%; background: repeating-linear-gradient(90deg, var(--mint) 0 14px, #5fd1ae 14px 16px); }
.px-rank { display:flex; justify-content:space-between; align-items:center; padding:8px 12px;
           border-bottom:2px dashed #d8d0ee; font-size:.95rem; }
.px-rank:last-child { border-bottom:none; }
.px-rank.me { background:#fff3cf; border-radius:4px; }
.px-rank .n { font-family:'Galmuri11',sans-serif; }
.stButton button, .stFormSubmitButton button { border:3px solid var(--ink) !important; border-radius:6px !important;
           box-shadow:3px 3px 0 var(--ink); }
.stButton button:active, .stFormSubmitButton button:active { transform: translate(2px,2px); box-shadow:1px 1px 0 var(--ink); }
.stTabs [data-baseweb="tab-list"] { gap: 2px; overflow-x:auto; }
.stTabs [data-baseweb="tab"] { padding: 6px 10px; }
@media (max-width: 640px) {
  .block-container { padding-left: 1rem; padding-right: 1rem; }
  .px-title { font-size: 1.35rem; }
  .stTabs [data-baseweb="tab"] { padding: 4px 6px; }
  .stTabs button p { font-size: .82rem; }
}
</style>
""",
        unsafe_allow_html=True,
    )


def page_header(subtitle: str):
    st.markdown('<div class="px-title">🕹️ 열품타 픽셀 챌린지</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="px-sub">{esc(subtitle)}</div>', unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════
# ⑤ 로그인 / 회원가입
# ════════════════════════════════════════════════════════════════

def lock_message(status) -> str:
    minutes = max(1, -(-int(status.get("seconds_left", 0)) // 60))
    return f"🔒 비밀번호를 여러 번 틀려서 잠겼어. 약 {minutes}분 뒤에 다시 시도해 줘."


def auth_page():
    page_header("열품타로 공부하고 · 인증하고 · 코인 모아 캐릭터 꾸미기!")
    login_tab, signup_tab = st.tabs(["👋 로그인", "✨ 처음이야? 가입하기"])

    with login_tab:
        with st.form("login_form"):
            nickname = st.text_input("별명")
            pin = st.text_input("숫자 비밀번호(PIN)", type="password")
            submitted = st.form_submit_button("로그인", type="primary", use_container_width=True)
        if submitted:
            do_login(nickname.strip(), pin)

    with signup_tab:
        st.caption("실명·전화번호는 받지 않아. 친구들이 알아볼 수 있는 별명만 정해 줘.")
        with st.form("signup_form"):
            nickname = st.text_input("사용할 별명 (한글/영문/숫자/_ 2~12자)")
            pin = st.text_input("숫자 비밀번호(PIN) 6~12자리", type="password")
            pin2 = st.text_input("비밀번호 다시 입력", type="password")
            class_code = st.text_input("반 참여 코드 (선생님/반장에게 받기)", type="password")
            submitted = st.form_submit_button("캐릭터 만들기", type="primary", use_container_width=True)
        if submitted:
            do_signup(nickname.strip(), pin, pin2, class_code.strip())


def do_login(nickname: str, pin: str):
    if not nickname or not pin:
        st.error("별명과 비밀번호를 모두 입력해 줘.")
        return
    guard_key = "p:" + nickname.lower()
    status = safe_rpc("guard_status", p_key=guard_key)
    if status is None:
        return
    if status.get("locked"):
        st.error(lock_message(status))
        return

    rows = safe_rpc("find_player_for_login", p_nickname=nickname)
    if rows is None:
        return
    if rows:
        row = rows[0]
        ok = hmac.compare_digest(hash_pin(pin, row["pin_salt"], int(row["pin_iterations"])), row["pin_hash"])
    else:
        hash_pin(pin, "dummy-salt", PIN_ITERATIONS)  # 없는 별명이어도 같은 시간이 걸리게
        ok = False

    status = safe_rpc("guard_record", p_key=guard_key, p_success=ok,
                      p_max_fail=LOGIN_MAX_FAIL, p_lock_minutes=LOGIN_LOCK_MINUTES)
    if status is None:
        return
    if ok:
        st.session_state.player_id = row["id"]
        st.rerun()
    elif status.get("locked"):
        st.error(lock_message(status))
    else:
        st.error("별명 또는 비밀번호가 맞지 않아.")


def do_signup(nickname: str, pin: str, pin2: str, class_code: str):
    configured = get_secret("CLASS_CODE")
    if not configured:
        st.error("관리자가 아직 반 참여 코드를 설정하지 않았어.")
    elif not hmac.compare_digest(class_code.encode(), configured.encode()):
        st.error("반 참여 코드가 맞지 않아.")
    elif not NICKNAME_RE.fullmatch(nickname):
        st.error("별명은 한글/영문/숫자/_ 로 2~12자만 쓸 수 있어. (띄어쓰기·특수문자 불가)")
    elif not (pin.isdigit() and 6 <= len(pin) <= 12):
        st.error("비밀번호는 숫자 6~12자리로 정해 줘.")
    elif weak_pin(pin):
        st.error("111111, 123456 같은 너무 쉬운 비밀번호는 안 돼.")
    elif pin != pin2:
        st.error("두 비밀번호가 서로 달라.")
    else:
        salt = secrets.token_hex(16)
        res = safe_rpc("create_player", p_nickname=nickname, p_pin_salt=salt,
                       p_pin_hash=hash_pin(pin, salt, PIN_ITERATIONS), p_pin_iterations=PIN_ITERATIONS)
        if res is None:
            return
        if res.get("ok"):
            st.session_state.player_id = res["id"]
            flash("success", f"🎉 {nickname} 캐릭터가 만들어졌어! 오늘 공부 시간을 인증해 봐.")
            st.rerun()
        elif res.get("code") == "nickname_taken":
            st.error("이미 누가 쓰고 있는 별명이야. 다른 별명을 골라 줘.")
        else:
            st.error("별명 형식이 올바르지 않아.")


# ════════════════════════════════════════════════════════════════
# ⑥ 학생 화면
# ════════════════════════════════════════════════════════════════

@st.cache_data(ttl=30, show_spinner=False)
def cached_leaderboard():
    return rpc("leaderboard") or []


@st.cache_data(ttl=30, show_spinner=False)
def cached_class_progress():
    return rpc("class_progress") or {}


def student_app():
    player_id = st.session_state.player_id
    rows = safe_rpc("get_player", p_player_id=player_id)
    if rows is None:
        st.stop()
    if not rows:  # 계정이 삭제된 경우
        st.session_state.player_id = None
        st.rerun()
    nickname = rows[0]["nickname"]

    coins = safe_rpc("player_balance", p_player_id=player_id)
    inventory = safe_rpc("player_inventory", p_player_id=player_id)
    submissions = safe_rpc("my_submissions", p_player_id=player_id, p_limit=30)
    if coins is None or inventory is None or submissions is None:
        st.stop()
    owned = set(inventory.get("owned", []))
    equipped = inventory.get("equipped", {})

    page_header(f"{nickname} 님, 오늘도 한 칸씩 레벨 업!")
    show_flash()

    tabs = st.tabs(["🏠 홈", "✏️ 인증", "🧍 캐릭터", "🛍️ 상점", "🏫 광장", "🏅 순위", "🤝 퀘스트"])
    with tabs[0]:
        home_tab(player_id, nickname, coins, owned, equipped, submissions)
    with tabs[1]:
        submit_tab(player_id, submissions)
    with tabs[2]:
        character_tab(player_id, nickname, owned, equipped)
    with tabs[3]:
        shop_tab(player_id, coins, owned, equipped)
    with tabs[4]:
        plaza_tab(nickname)
    with tabs[5]:
        ranking_tab(nickname)
    with tabs[6]:
        quest_tab()

    st.divider()
    if st.button("로그아웃", key="logout_student"):
        st.session_state.player_id = None
        st.rerun()


def home_tab(player_id, nickname, coins, owned, equipped, submissions):
    today = kst_today()
    today_sub = next((s for s in submissions if s["study_date"] == today.isoformat()
                      and s["status"] in ("pending", "approved")), None)
    if today_sub is None:
        today_html = "아직 오늘 인증을 안 했어. <b>✏️ 인증</b> 탭에서 제출해 줘!"
    elif today_sub["status"] == "pending":
        today_html = f"오늘 {fmt_minutes(today_sub['claimed_minutes'])} 제출 완료 · 관리자 확인을 기다리는 중 ⏳"
    else:
        today_html = f"오늘 {fmt_minutes(today_sub['approved_minutes'])} 승인 완료! ✅"

    st.markdown(
        f"""
<div class="px-card violet"><div class="px-row">
  <div class="px-avatar">{avatar_svg(equipped, 7)}</div>
  <div>
    <div class="px-stat">{esc(nickname)}</div>
    <div class="px-label">보유 코인</div><div class="px-stat">🪙 {int(coins)}</div>
    <div class="px-label" style="margin-top:6px">보유 아이템 {len(owned)} / {len(catalog())}</div>
  </div>
</div></div>
<div class="px-card gold"><b class="px-font">📅 오늘의 인증</b><br/>{today_html}</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### 최근 인증 상태")
    if not submissions:
        st.info("아직 제출한 기록이 없어.")
    for s in submissions[:5]:
        minutes = s["approved_minutes"] if s["status"] == "approved" else s["claimed_minutes"]
        reason = (f"<br/><span class='px-label'>반려 사유: {esc(s['reject_reason'])} · "
                  f"같은 날짜로 다시 제출할 수 있어</span>") if s["status"] == "rejected" else ""
        st.markdown(
            f"<div class='px-card' style='padding:8px 12px'>"
            f"<span class='px-badge {s['status']}'>{STATUS_LABEL[s['status']]}</span> "
            f"<b>{esc(s['study_date'])}</b> · {fmt_minutes(minutes)}{reason}</div>",
            unsafe_allow_html=True,
        )

    with st.expander("🪙 코인 변동 기록 보기"):
        history = safe_rpc("coin_history", p_player_id=player_id, p_limit=30)
        if history:
            st.dataframe(pd.DataFrame([{
                "날짜": to_kst(h["created_at"])[:10], "내용": h["reason"],
                "코인": f"+{h['amount']}" if h["amount"] > 0 else str(h["amount"]),
            } for h in history]), hide_index=True, use_container_width=True)
        elif history is not None:
            st.caption("아직 코인 변동이 없어.")


def submit_tab(player_id, submissions):
    today = kst_today()
    earliest = today - timedelta(days=SUBMIT_WINDOW_DAYS - 1)
    st.markdown("#### ✏️ 오늘 공부 시간 인증하기")
    st.caption(f"열품타에 기록된 그날의 공부 시간을 그대로 입력해 줘. "
               f"관리자가 반 열품타 그룹 기록과 비교해서 승인해. (오늘 포함 최근 {SUBMIT_WINDOW_DAYS}일까지 제출 가능)")

    study_date = st.date_input("공부한 날짜", value=today, min_value=earliest, max_value=today,
                               format="YYYY-MM-DD", key="submit_date")
    c1, c2 = st.columns(2)
    hours = c1.number_input("시간", min_value=0, max_value=MAX_DAILY_MINUTES // 60, value=0, step=1, key="submit_h")
    minutes = c2.number_input("분", min_value=0, max_value=59, value=0, step=1, key="submit_m")
    total = int(hours) * 60 + int(minutes)

    active = next((s for s in submissions if s["study_date"] == study_date.isoformat()
                   and s["status"] in ("pending", "approved")), None)
    if active:
        st.info(f"{study_date.isoformat()} 은(는) 이미 제출했어 ({STATUS_LABEL[active['status']]}). "
                f"같은 날짜는 한 번만 보상받을 수 있어.")
    elif total > 0:
        r = calc_rewards(min(total, MAX_DAILY_MINUTES))
        st.markdown(
            f"<div class='px-card mint'>입력: <b>{fmt_minutes(total)}</b><br/>"
            f"승인되면 예상 코인: 출석 {r['attendance']} + 시간 보너스 {r['bonus']} = "
            f"<b>🪙 {r['total']}</b></div>",
            unsafe_allow_html=True,
        )

    if st.button("제출하기", type="primary", use_container_width=True, disabled=bool(active), key="submit_btn"):
        if total <= 0:
            st.error("공부 시간이 0분이면 제출할 수 없어.")
        elif total > MAX_DAILY_MINUTES:
            st.error(f"하루 최대 {MAX_DAILY_MINUTES // 60}시간까지만 입력할 수 있어.")
        else:
            res = safe_rpc("submit_study", p_player_id=player_id,
                           p_study_date=study_date.isoformat(), p_minutes=total)
            if res is not None:
                if res.get("ok"):
                    flash("success", f"📨 {study_date.isoformat()} · {fmt_minutes(total)} 제출 완료! "
                                     f"관리자가 확인하면 코인이 들어와.")
                    st.rerun()
                st.error({
                    "zero_minutes": "공부 시간이 0분이면 제출할 수 없어.",
                    "too_long": f"하루 최대 {MAX_DAILY_MINUTES // 60}시간까지만 입력할 수 있어.",
                    "future_date": "미래 날짜는 제출할 수 없어.",
                    "too_old": f"오늘 포함 최근 {SUBMIT_WINDOW_DAYS}일 안의 기록만 제출할 수 있어.",
                    "already_submitted": "이 날짜는 이미 제출했어 (검토 중이거나 승인됨).",
                }.get(res.get("code"), "제출하지 못했어. 다시 로그인해 줘."))

    st.markdown("#### 내 제출 기록")
    if submissions:
        st.dataframe(pd.DataFrame([{
            "날짜": s["study_date"],
            "입력 시간": fmt_minutes(s["claimed_minutes"]),
            "승인 시간": fmt_minutes(s["approved_minutes"]) if s["approved_minutes"] else "-",
            "상태": STATUS_LABEL.get(s["status"], s["status"]),
            "반려 사유": s["reject_reason"] or "",
        } for s in submissions]), hide_index=True, use_container_width=True)
    else:
        st.caption("아직 제출 기록이 없어.")


NONE = "_none_"   # "착용 안 함" 표시용 값 (None 을 쓰면 Streamlit 이 빈 선택으로 처리함)


def character_tab(player_id, nickname, owned, equipped):
    st.markdown("#### 🧍 내 캐릭터 꾸미기")
    preview_box = st.container()   # 미리보기를 맨 위에 보여 주기 위한 자리
    if not owned:
        st.info("아직 아이템이 없어. 코인을 모아 🛍️ 상점에서 사 봐!")

    selection = {}
    for category in CATEGORIES:
        choices = [NONE] + [i["id"] for i in catalog(include_hidden=True)
                            if i["category"] == category and i["id"] in owned]
        current = equipped.get(category) if equipped.get(category) in choices else NONE
        picked = st.selectbox(
            category, choices, index=choices.index(current),
            format_func=lambda x: "착용 안 함" if x == NONE else (item_info(x) or {"name": x})["name"],
            key=f"equip_{category}", disabled=len(choices) == 1,
        )
        selection[category] = None if picked == NONE else picked

    preview = {c: v for c, v in selection.items() if v}
    preview_box.markdown(
        f"<div class='px-card violet' style='text-align:center'>"
        f"<div class='px-avatar'>{avatar_svg(preview, 9)}</div>"
        f"<div class='px-stat' style='margin-top:8px'>{esc(nickname)}</div>"
        f"<div class='px-label'>미리보기 · [이대로 저장]을 눌러야 적용돼</div></div>",
        unsafe_allow_html=True,
    )

    changed = [c for c in CATEGORIES if selection[c] != equipped.get(c)]
    if st.button("💾 이대로 저장", type="primary", use_container_width=True, disabled=not changed, key="equip_save"):
        for category in changed:
            res = safe_rpc("equip_item", p_player_id=player_id, p_category=category, p_item_id=selection[category])
            if res is None:
                return
            if not res.get("ok"):
                st.error("가지고 있지 않은 아이템은 착용할 수 없어.")
                return
        cached_plaza.clear()
        flash("success", "👕 착용 상태를 저장했어!")
        st.rerun()


def shop_tab(player_id, coins, owned, equipped):
    st.markdown(f"#### 🛍️ 아이템 상점 · 내 코인 🪙 {int(coins)}")
    st.caption("아이템은 한 번만 살 수 있고, 산 뒤에는 🧍 캐릭터 탭에서 착용해.")
    design_ticket_box(player_id, coins)

    items = catalog()
    cols = st.columns(2)
    for idx, item in enumerate(items):
        with cols[idx % 2]:
            with st.container(border=True):
                preview = dict(equipped)
                preview[item["category"]] = item["id"]
                maker = (f"<div class='px-label'>🎨 만든 사람: {esc(item['creator'])}</div>"
                         if item.get("creator") else
                         ("<div class='px-label'>🎨 학생 디자인</div>" if item.get("custom") else ""))
                st.markdown(
                    f"<div style='text-align:center'><div class='px-avatar'>{avatar_svg(preview, 5)}</div>"
                    f"<div class='px-font' style='margin-top:6px'>{esc(item['name'])}</div>"
                    f"<span class='px-badge'>{esc(item['category'])}</span>"
                    f"<span class='px-badge'>{esc(item['rarity'])}</span>{maker}"
                    f"<div class='px-stat'>🪙 {item['price']}</div></div>",
                    unsafe_allow_html=True,
                )
                if item["id"] in owned:
                    st.button("✔ 보유 중", disabled=True, key=f"owned_{item['id']}", use_container_width=True)
                elif coins < item["price"]:
                    st.button(f"🪙 {item['price'] - coins} 부족", disabled=True,
                              key=f"poor_{item['id']}", use_container_width=True)
                elif st.button("구매하기", type="primary", key=f"buy_{item['id']}", use_container_width=True):
                    buy_item(player_id, item)


TICKET_STATUS = {"unused": "⏳ 그림 기다리는 중", "used": "✅ 등록 완료", "refunded": "↩️ 환불됨"}


def design_ticket_box(player_id, coins):
    """디자인 등록권 카드 (구매는 확인 버튼을 한 번 더 눌러야 진행)"""
    tickets = safe_rpc("my_tickets", p_player_id=player_id) or []
    unused = sum(1 for t in tickets if t["status"] == "unused")
    with st.container(border=True):
        st.markdown(
            f"<div class='px-font' style='font-size:1.05rem'>🎨 디자인 등록권 · 🪙 {DESIGN_TICKET_PRICE}</div>"
            f"<div style='margin:6px 0'>내가 그린 옷을 상점에 올릴 수 있어! "
            f"등록되면 <b>내 옷은 무료로 받고</b>, 친구들이 코인으로 살 수 있어.</div>"
            f"<div class='px-label'>① 등록권 사기 → ② 도안 받아서 그리기 → ③ 관리자에게 그림 보내기 "
            f"(아이템 이름·부위·원하는 가격도 같이) → ④ 관리자가 등록</div>",
            unsafe_allow_html=True,
        )
        c1, c2 = st.columns(2)
        c1.download_button("📥 도안 받기", data=template_png(), file_name="옷그리기_도안_320x380.png",
                           mime="image/png", use_container_width=True, key="dl_template")
        confirm_key = "ticket_confirm"
        if unused >= MAX_UNUSED_TICKETS:
            c2.button(f"안 쓴 등록권 {unused}장 보유 중", disabled=True, use_container_width=True, key="t_max")
        elif coins < DESIGN_TICKET_PRICE:
            c2.button(f"🪙 {DESIGN_TICKET_PRICE - coins} 부족", disabled=True, use_container_width=True, key="t_poor")
        elif not st.session_state.get(confirm_key):
            if c2.button("등록권 사기", type="primary", use_container_width=True, key="t_buy"):
                st.session_state[confirm_key] = True
                st.rerun()
        else:
            c2.warning(f"🪙 {DESIGN_TICKET_PRICE} 을 써서 등록권을 살까?")
            y, n = st.columns(2)
            if y.button("✅ 살게", type="primary", use_container_width=True, key="t_yes"):
                st.session_state[confirm_key] = False
                res = safe_rpc("buy_design_ticket", p_player_id=player_id, p_price=DESIGN_TICKET_PRICE,
                               p_max_unused=MAX_UNUSED_TICKETS)
                if res is not None:
                    if res.get("ok"):
                        flash("success", f"🎨 디자인 등록권 #{res['ticket_id']} 구매 완료! 도안에 그려서 관리자에게 보내 줘.")
                        st.rerun()
                    st.error({"not_enough": "코인이 부족해.",
                              "too_many_unused": f"안 쓴 등록권은 {MAX_UNUSED_TICKETS}장까지만 가질 수 있어."
                              }.get(res.get("code"), "구매하지 못했어. 다시 시도해 줘."))
            if n.button("취소", use_container_width=True, key="t_no"):
                st.session_state[confirm_key] = False
                st.rerun()
        if tickets:
            with st.expander(f"내 등록권 {len(tickets)}장 (안 쓴 것 {unused}장)"):
                for t in tickets:
                    extra = f" · {esc(t['item_name'])}" if t.get("item_name") else ""
                    note = f" · 사유: {esc(t['note'])}" if t.get("note") and t["status"] == "refunded" else ""
                    st.markdown(f"#{t['id']} · {TICKET_STATUS.get(t['status'], t['status'])}{extra}{note} "
                                f"<span class='px-label'>({to_kst(t['bought_at'])[:10]})</span>",
                                unsafe_allow_html=True)


def buy_item(player_id, item):
    res = safe_rpc("purchase_item", p_player_id=player_id, p_item_id=item["id"],
                   p_item_name=item["name"], p_price=item["price"])
    if res is None:
        return  # 실패 시 DB가 전부 취소하므로 코인도 그대로
    if res.get("ok"):
        flash("success", f"🎁 {item['name']} 구매 완료! 남은 코인 🪙 {res['balance']}")
        st.rerun()
    elif res.get("code") == "already_owned":
        st.warning("이미 가지고 있는 아이템이야.")
    elif res.get("code") == "not_available":
        st.warning("지금은 판매하지 않는 아이템이야.")
    elif res.get("code") == "not_enough":
        st.error(f"코인이 부족해. (현재 🪙 {res.get('balance', 0)})")
    else:
        st.error("구매하지 못했어. 다시 로그인해 줘.")


def plaza_tab(my_nickname):
    st.markdown("#### 🏫 우리 반 광장")
    try:
        rows, bg = cached_plaza()
    except DBError:
        st.error("⚠️ 광장을 불러오지 못했어. 잠시 후 다시 시도해 줘.")
        return
    if not rows:
        st.info("아직 아무도 없어.")
        return
    st.markdown(f"<div class='px-card' style='padding:6px'>{plaza_svg(rows, my_nickname, bg.get('kind', 'classroom'), bg.get('image'))}</div>",
                unsafe_allow_html=True)
    st.caption(f"친구 {len(rows)}명 · 이름표의 등수는 승인된 공부 시간 순위야 (🌱 = 아직 승인된 기록 없음). "
               f"보라색 테두리가 나야! 옷을 바꾸면 최대 30초 뒤에 반영돼.")


def ranking_tab(my_nickname):
    st.markdown("#### 🏅 개인 공부 시간 순위")
    st.caption("관리자가 승인한 공부 시간만 합산해. (최대 30초 늦게 반영될 수 있어)")
    try:
        board = cached_leaderboard()
    except DBError:
        st.error("⚠️ 순위를 불러오지 못했어. 잠시 후 다시 시도해 줘.")
        return
    if not board:
        st.info("아직 참가자가 없어.")
        return
    medals = {1: "🥇", 2: "🥈", 3: "🥉"}
    rows_html, rank, prev = [], 0, None
    for i, r in enumerate(board, start=1):
        if r["total_minutes"] != prev:  # 같은 시간이면 같은 등수
            rank, prev = i, r["total_minutes"]
        me = " me" if r["nickname"] == my_nickname else ""
        rows_html.append(
            f"<div class='px-rank{me}'><span class='n'>{medals.get(rank, f'{rank}위')} {esc(r['nickname'])}</span>"
            f"<span>{fmt_minutes(r['total_minutes'])} · {r['study_days']}일</span></div>"
        )
    st.markdown("<div class='px-card'>" + "".join(rows_html) + "</div>", unsafe_allow_html=True)


def quest_tab():
    st.markdown("#### 🤝 반 공동 퀘스트")
    try:
        prog = cached_class_progress()
    except DBError:
        st.error("⚠️ 퀘스트 정보를 불러오지 못했어. 잠시 후 다시 시도해 줘.")
        return
    total_min = int(prog.get("total_minutes", 0))
    goal_h = int(prog.get("goal_hours", 300))
    pct = min(100.0, total_min / (goal_h * 60) * 100) if goal_h else 0.0
    done = total_min >= goal_h * 60
    title = "🎉 퀘스트 클리어! 우리 반 최고!" if done else f"우리 반 다 같이 {goal_h}시간 공부하기"
    stages = "".join(
        f"<span class='px-badge {'approved' if pct >= s else ''}'>{'★' if pct >= s else '☆'} {s}%</span>"
        for s in (25, 50, 75, 100))
    st.markdown(
        f"""
<div class="px-card {'gold' if done else 'mint'}">
  <div class="px-font" style="font-size:1.1rem">{title}</div>
  <div style="margin:10px 0 6px 0" class="px-bar"><div style="width:{pct:.1f}%"></div></div>
  <div><b>{fmt_minutes(total_min)}</b> / {goal_h}시간 · <b>{pct:.1f}%</b></div>
  <div style="margin-top:8px">{stages}</div>
  <div class="px-label" style="margin-top:6px">참여 인원 {prog.get('contributors', 0)} / {prog.get('players', 0)}명 ·
  승인된 공부 시간만 반영돼</div>
</div>""",
        unsafe_allow_html=True,
    )


# ════════════════════════════════════════════════════════════════
# ⑦ 관리자 화면  (주소 뒤에 ?admin)
# ════════════════════════════════════════════════════════════════

def admin_page():
    page_header("관리자 화면 · 인증 검토")
    admin_pw = get_secret("ADMIN_PASSWORD")
    if len(admin_pw) < 8:
        st.error("Secrets 에 ADMIN_PASSWORD(8자 이상)를 먼저 설정해 줘.")
        return

    if not st.session_state.get("admin_ok"):
        with st.form("admin_login"):
            pw = st.text_input("관리자 비밀번호", type="password")
            submitted = st.form_submit_button("관리자 로그인", type="primary", use_container_width=True)
        if submitted:
            status = safe_rpc("guard_status", p_key="admin")
            if status is None:
                return
            if status.get("locked"):
                st.error(lock_message(status))
                return
            ok = hmac.compare_digest(pw.encode(), admin_pw.encode())
            status = safe_rpc("guard_record", p_key="admin", p_success=ok,
                              p_max_fail=LOGIN_MAX_FAIL, p_lock_minutes=LOGIN_LOCK_MINUTES)
            if ok:
                st.session_state.admin_ok = True
                st.session_state.player_id = None
                st.rerun()
            elif status and status.get("locked"):
                st.error(lock_message(status))
            else:
                st.error("비밀번호가 맞지 않아.")
        return

    show_flash()
    pending = safe_rpc("pending_submissions")
    if pending is None:
        return
    t1, t2, t4, t3 = st.tabs([f"📋 검토 대기 ({len(pending)})", "🗂️ 처리 내역", "🎨 아이템 등록", "⚙️ 반 설정·현황"])
    with t1:
        admin_review(pending)
    with t2:
        admin_history()
    with t4:
        admin_items()
    with t3:
        admin_settings()

    st.divider()
    if st.button("관리자 로그아웃", key="logout_admin"):
        st.session_state.admin_ok = False
        st.rerun()


def admin_review(pending):
    if not pending:
        st.success("검토할 제출이 없어요. 오늘 검토 끝! 🎉")
        return
    st.caption("열품타 그룹 기록과 비교 → 맞으면 [승인], 다르면 시간을 고쳐서 승인하거나 사유를 적고 [반려]. "
               "승인하면 코인이 자동으로 지급되고, 같은 보상은 절대 두 번 지급되지 않습니다.")
    for sub in pending:
        sid = sub["id"]
        claimed = int(sub["claimed_minutes"])
        with st.container(border=True):
            warn = f" · ⚠️ 이 날짜 반려 {sub['rejected_before']}회" if sub["rejected_before"] else ""
            st.markdown(f"**{esc(sub['nickname'])}** · 📅 {sub['study_date']} · "
                        f"학생 입력 **{claimed // 60}시간 {claimed % 60}분**{warn}")

            c1, c2 = st.columns(2)
            ah = c1.number_input("승인 시간", 0, MAX_DAILY_MINUTES // 60, claimed // 60, key=f"ah_{sid}")
            am = c2.number_input("승인 분", 0, 59, claimed % 60, key=f"am_{sid}")
            approved = int(ah) * 60 + int(am)
            r = calc_rewards(approved)
            changed = " (입력값에서 수정됨)" if approved != claimed else ""
            st.markdown(
                f"예상 보상{changed}: 출석 **{r['attendance']}** + 공부시간 **{r['bonus']}** "
                f"= 총 **🪙 {r['total']}**  · 상태: ⏳ 검토 대기")

            b1, b2 = st.columns(2)
            if b1.button("✅ 승인", type="primary", key=f"ok_{sid}", use_container_width=True):
                if approved < 1 or approved > MAX_DAILY_MINUTES:
                    st.error("승인 시간은 1분 ~ 16시간 사이여야 해요. 0분이면 반려해 주세요.")
                else:
                    res = safe_rpc("approve_submission", fail_msg=(
                        "DB 연결 오류로 승인 결과를 확인하지 못했어요. 새로고침해서 상태를 확인하세요. "
                        "(오류가 났다면 코인도 지급되지 않았고, 다시 눌러도 중복 지급되지 않아요)"),
                        p_submission_id=sid, p_approved_minutes=approved, p_rules=REWARD_RULES)
                    handle_review_result(res, f"{sub['nickname']} 승인 · 🪙 {{coins}} 지급")
            reason = st.text_input("반려 사유 (반려할 때만)", key=f"rr_{sid}", max_chars=200,
                                   placeholder="예) 열품타 기록과 시간이 달라요")
            if b2.button("↩️ 반려", key=f"no_{sid}", use_container_width=True):
                if not reason.strip():
                    st.error("반려 사유를 적어 주세요. (학생 화면에 보여요)")
                else:
                    res = safe_rpc("reject_submission", p_submission_id=sid, p_reason=reason.strip())
                    handle_review_result(res, f"{sub['nickname']} 반려 완료")


def handle_review_result(res, ok_msg):
    if res is None:
        return
    if res.get("ok"):
        flash("success", ok_msg.format(coins=res.get("coins_granted", 0)))
    elif res.get("code") == "already_reviewed":
        flash("warning", "이미 처리된 제출이에요. (중복 지급 없음)")
    else:
        flash("error", f"처리하지 못했어요: {res.get('code')}")
    cached_leaderboard.clear()
    cached_class_progress.clear()
    cached_plaza.clear()
    st.rerun()


def admin_history():
    rows = safe_rpc("recent_reviews", p_limit=50)
    if not rows:
        st.caption("아직 처리한 기록이 없어요.")
        return
    st.dataframe(pd.DataFrame([{
        "처리 시각": to_kst(r["reviewed_at"]),
        "별명": r["nickname"], "날짜": r["study_date"],
        "학생 입력": fmt_minutes(r["claimed_minutes"]),
        "승인 시간": fmt_minutes(r["approved_minutes"]) if r["approved_minutes"] else "-",
        "결과": STATUS_LABEL.get(r["status"], r["status"]),
        "지급 코인": r["coins"], "반려 사유": r["reject_reason"] or "",
    } for r in rows]), hide_index=True, use_container_width=True)


def admin_items():
    """학생 디자인 등록: 등록권 확인 → 그림 올리기 → 미리보기 → 등록"""
    tickets = safe_rpc("ticket_list", p_limit=200)
    if tickets is None:
        return
    open_tickets = [t for t in tickets if t["status"] == "unused"]

    st.markdown(f"#### 🎟️ 그림을 기다리는 등록권 ({len(open_tickets)})")
    if not open_tickets:
        st.caption("지금은 기다리는 등록권이 없어요.")
    for t in open_tickets:
        with st.expander(f"#{t['id']} · {t['nickname']} · {to_kst(t['bought_at'])[:16]} · 🪙{t['price_paid']}"):
            st.caption("그림이 부적절하거나 등록하지 않을 때만 환불하세요. 환불하면 코인이 학생에게 돌아가요.")
            reason = st.text_input("환불 사유 (학생에게 보여요)", key=f"rf_reason_{t['id']}", max_chars=200)
            if st.button("↩️ 환불", key=f"rf_{t['id']}"):
                if not reason.strip():
                    st.error("환불 사유를 적어 주세요.")
                else:
                    res = safe_rpc("refund_ticket", p_ticket_id=t["id"], p_reason=reason.strip())
                    if res is not None:
                        flash("success" if res.get("ok") else "warning",
                              f"#{t['id']} 환불 완료 (🪙 {res.get('refunded', 0)})" if res.get("ok")
                              else "이미 처리된 등록권이에요.")
                        st.rerun()

    st.divider()
    st.markdown("#### ➕ 새 아이템 등록")
    st.caption("학생이 도안(320×380)에 그린 그림을 올리면 자동으로 도트(16×19칸)로 바뀌어요. "
               "미리보기를 확인하고 등록하면 바로 상점에 올라가요.")
    st.session_state.setdefault("reg_nonce", 0)
    up = st.file_uploader("그림 파일 (PNG 추천)", type=["png", "jpg", "jpeg"], key=f"reg_file_{st.session_state.reg_nonce}")
    c1, c2 = st.columns(2)
    white_empty = c1.checkbox("흰색 = 배경(투명)으로 처리", value=True, key="reg_white",
                              help="흰 배경에 그린 그림이면 켜 두세요. 흰색 옷을 그렸다면 끄세요.")
    remove_base = c2.checkbox("기본 캐릭터 부분 지우기", value=False, key="reg_rmbase",
                              help="학생이 밑그림(기본 캐릭터)까지 같이 저장한 경우에만 켜세요.")

    grid = None
    if up is not None:
        if up.size > 5 * 1024 * 1024:
            st.error("파일이 너무 커요 (5MB 이하).")
        else:
            grid, notes = png_to_grid(up.getvalue(), white_is_empty=white_empty, remove_base=remove_base)
            for n in notes:
                (st.caption if grid else st.error)(n)

    name = st.text_input("아이템 이름 (1~20자)", key="reg_name", max_chars=20)
    c3, c4, c5 = st.columns(3)
    category = c3.selectbox("부위", CATEGORIES, key="reg_cat",
                            help="같은 부위 아이템은 하나만 착용할 수 있어요.")
    price = c4.number_input("가격 (코인)", min_value=1, max_value=1000, value=50, step=5, key="reg_price")
    rarity = c5.selectbox("등급", RARITIES, key="reg_rarity")

    ticket_opts = [None] + [t["id"] for t in open_tickets]
    ticket_label = {t["id"]: f"#{t['id']} · {t['nickname']}" for t in open_tickets}
    ticket_id = st.selectbox("사용할 등록권 (만든 학생에게 무료 지급)", ticket_opts,
                             format_func=lambda x: "없음 (관리자 직접 등록)" if x is None else ticket_label[x],
                             key="reg_ticket")
    creator_id = None
    if ticket_id is None:
        players = safe_rpc("player_list") or []
        p_opts = [None] + [p["id"] for p in players]
        p_label = {p["id"]: p["nickname"] for p in players}
        creator_id = st.selectbox("만든 사람 (선택)", p_opts,
                                  format_func=lambda x: "표시 안 함" if x is None else p_label[x], key="reg_creator")

    if grid:
        a, b = st.columns(2)
        a.markdown(f"<div style='text-align:center'><div class='px-avatar'>{svg_from_layers([grid], 8, with_base=False)}</div>"
                   f"<div class='px-label'>아이템만</div></div>", unsafe_allow_html=True)
        b.markdown(f"<div style='text-align:center'><div class='px-avatar'>{avatar_svg({}, 8, extra={category: grid})}</div>"
                   f"<div class='px-label'>캐릭터에 입힌 모습 ({esc(category)})</div></div>", unsafe_allow_html=True)

    ready = bool(grid) and bool(name.strip())
    if st.button("🎨 상점에 등록", type="primary", use_container_width=True, disabled=not ready, key="reg_go"):
        res = safe_rpc("register_custom_item", p_name=name.strip(), p_category=category, p_price=int(price),
                       p_rarity=rarity, p_sprite=grid, p_ticket_id=ticket_id, p_creator_id=creator_id)
        if res is not None:
            if res.get("ok"):
                load_custom_items.clear()
                st.session_state.reg_nonce += 1          # 파일 선택 칸 비우기
                for k in ("reg_name",):
                    st.session_state.pop(k, None)
                flash("success", f"🎉 '{name.strip()}' 등록 완료! (아이템 번호 {res['id']}) 상점에 바로 보여요.")
                st.rerun()
            st.error({"ticket_closed": "이미 사용했거나 환불된 등록권이에요.",
                      "bad_sprite": "그림 변환 결과가 올바르지 않아요. 다시 올려 주세요.",
                      "bad_name": "이름은 1~20자로 적어 주세요."}.get(res.get("code"), f"등록 실패: {res.get('code')}"))
    if not ready:
        st.caption("그림을 올리고 이름을 적으면 [상점에 등록] 버튼이 켜져요.")

    st.divider()
    customs = load_custom_items()
    st.markdown(f"#### 🗂️ 등록된 학생 디자인 ({len(customs)})")
    if not customs:
        st.caption("아직 등록된 학생 디자인이 없어요.")
    for c in customs:
        with st.container(border=True):
            l, r = st.columns([1, 3])
            l.markdown(f"<div class='px-avatar'>{avatar_svg({}, 4, extra={c['category']: c['sprite']})}</div>",
                       unsafe_allow_html=True)
            r.markdown(f"**{esc(c['name'])}** · {esc(c['category'])} · 🪙{c['price']} · {esc(c['rarity'])}  \n"
                       f"만든 사람: {esc(c['creator'] or '-')} · 보유 {c['owners']}명 · "
                       f"{'🟢 판매 중' if c['active'] else '⚫ 숨김'} · `{c['id']}`")
            label = "상점에서 숨기기" if c["active"] else "다시 판매하기"
            if r.button(label, key=f"vis_{c['id']}"):
                res = safe_rpc("set_custom_item_active", p_item_id=c["id"], p_active=not c["active"])
                if res and res.get("ok"):
                    load_custom_items.clear()
                    flash("success", f"'{c['name']}' → {'숨김' if c['active'] else '판매 중'}")
                    st.rerun()
    st.caption("숨겨도 이미 산 학생은 계속 착용할 수 있어요.")

    if tickets and any(t["status"] != "unused" for t in tickets):
        with st.expander("등록권 전체 기록"):
            st.dataframe(pd.DataFrame([{
                "번호": t["id"], "학생": t["nickname"], "상태": TICKET_STATUS.get(t["status"], t["status"]),
                "아이템": t["item_name"] or "", "산 날": to_kst(t["bought_at"])[:10], "메모": t["note"] or "",
            } for t in tickets]), hide_index=True, use_container_width=True)


def admin_settings():
    st.markdown("#### 🏫 광장 배경")
    try:
        rows, bg = cached_plaza()
    except DBError:
        rows, bg = [], {}
    cur = bg.get("kind", "classroom")
    kinds = list(PLAZA_BACKGROUNDS)
    pick = st.radio("배경 고르기", kinds, index=kinds.index(cur) if cur in kinds else 0,
                    format_func=lambda k: PLAZA_BACKGROUNDS[k] + (" (지금)" if k == cur else ""),
                    horizontal=True, key="bg_pick")
    new_uri = None
    if pick == "custom":
        st.caption("추천: 가로 540 × 세로 740 그림, 위에서 215 지점(약 30%)부터 아래는 바닥. "
                   "광장 크기가 인원수에 따라 달라서 가장자리가 조금 잘릴 수 있어요.")
        up = st.file_uploader("배경 그림 올리기 (PNG/JPG)",
                              type=["png", "jpg", "jpeg"], key="bg_file")
        if up is not None:
            if up.size > 8 * 1024 * 1024:
                st.error("파일이 너무 커요 (8MB 이하).")
            else:
                new_uri, err = image_to_data_uri(up.getvalue())
                if err:
                    st.error(err)
        elif not bg.get("image"):
            st.caption("아직 올린 그림이 없어요. 그림을 올려 주세요.")
    preview_img = new_uri or bg.get("image")
    sample = rows or [{"player_id": "sample", "nickname": "예시", "total_minutes": 0, "equipped": {}}]
    st.markdown(f"<div class='px-card' style='padding:6px'>{plaza_svg(sample, '', pick, preview_img)}</div>",
                unsafe_allow_html=True)
    st.caption("미리보기예요. [배경 저장]을 눌러야 학생 화면에 적용돼요.")
    can_save = pick != "custom" or bool(new_uri or bg.get("image"))
    if st.button("배경 저장", type="primary", disabled=not can_save, key="bg_save"):
        res = safe_rpc("set_plaza_bg", p_kind=pick, p_image=new_uri if pick == "custom" else None)
        if res is not None:
            if res.get("ok"):
                cached_plaza.clear()
                flash("success", f"광장 배경을 '{PLAZA_BACKGROUNDS[pick]}' 로 바꿨어요.")
                st.rerun()
            st.error({"bad_image": "그림 형식이 올바르지 않아요.", "no_image": "먼저 그림을 올려 주세요."}
                     .get(res.get("code"), f"저장 실패: {res.get('code')}"))
    st.divider()

    prog = safe_rpc("class_progress") or {}
    goal = int(prog.get("goal_hours", 300))
    st.markdown(f"**반 공동 목표:** {goal}시간 · 현재 {fmt_minutes(prog.get('total_minutes', 0))}")
    new_goal = st.number_input("반 공동 목표 시간(시간)", min_value=1, max_value=100000, value=goal, step=10)
    if st.button("목표 저장", key="save_goal"):
        res = safe_rpc("set_class_goal", p_hours=int(new_goal))
        if res and res.get("ok"):
            cached_class_progress.clear()
            flash("success", f"반 공동 목표를 {int(new_goal)}시간으로 저장했어요.")
            st.rerun()

    st.markdown("**보상 규칙** (app.py 맨 위 `REWARD_RULES` 에서 수정)")
    lines = [f"- 출석 승인: {REWARD_RULES['attendance']}코인"]
    lines += [f"- {fmt_minutes(r['minutes'])} 이상: +{r['coins']}코인" for r in REWARD_RULES["milestones"]]
    st.markdown("\n".join(lines))

    st.markdown("**개인 순위 (승인 기준)**")
    board = safe_rpc("leaderboard") or []
    if board:
        st.dataframe(pd.DataFrame([{"별명": b["nickname"], "누적": fmt_minutes(b["total_minutes"]),
                                    "인증 일수": b["study_days"]} for b in board]),
                     hide_index=True, use_container_width=True)


# ════════════════════════════════════════════════════════════════
# ⑧ 시작
# ════════════════════════════════════════════════════════════════

def main():
    st.set_page_config(page_title="열품타 픽셀 챌린지", page_icon="🕹️", layout="centered")
    inject_css()

    if get_db() is None:
        page_header("설정이 필요해요")
        try:
            found = set(st.secrets.keys())
        except Exception as exc:
            print(f"[SECRETS ERROR] {exc!r}")
            if "no-secrets-found" in repr(exc):
                st.error("Secrets 가 비어 있어요. Manage app → ⋮ → Settings → Secrets 에 4줄을 넣고 "
                         "[Save] 를 눌렀는지 확인해 주세요.")
                st.stop()
            st.error("Secrets 형식(TOML)에 오류가 있어요. 확인할 것: ① 한 항목은 반드시 한 줄 "
                     "(이름 = \"값\" 사이에 엔터 금지) ② 값은 큰따옴표 \" \" 로 감싸기 "
                     "③ 따옴표가 짝이 맞는지. 고친 뒤 Save → Reboot app")
            st.stop()
        needed = ["SUPABASE_URL", "SUPABASE_SECRET_KEY", "CLASS_CODE", "ADMIN_PASSWORD"]
        missing = [k for k in needed if k not in found]
        if "SUPABASE_SERVICE_ROLE_KEY" in found and "SUPABASE_SECRET_KEY" in missing:
            missing.remove("SUPABASE_SECRET_KEY")
        st.error("데이터베이스 연결 정보가 없어요. Secrets 에 아래 이름이 없거나 값이 비어 있어요: "
                 + ", ".join(missing or ["SUPABASE_URL / SUPABASE_SECRET_KEY 값"]))
        st.caption("지금 Secrets 에서 읽힌 이름: " + (", ".join(sorted(found)) or "(없음)"))
        st.stop()

    if "db_checked" not in st.session_state:
        try:
            rpc("kst_today")
            st.session_state.db_checked = True
        except DBError:
            page_header("연결 확인 실패")
            st.error("Supabase 에 연결하지 못했어요. ① SUPABASE_URL / 키가 맞는지 ② schema.sql 을 실행했는지 "
                     "확인해 주세요. (자세한 오류는 Streamlit Cloud 의 Manage app > 로그에 있어요)")
            st.stop()

    st.session_state.setdefault("player_id", None)
    st.session_state.setdefault("admin_ok", False)

    if "admin" in st.query_params:
        admin_page()
    elif st.session_state.player_id:
        student_app()
    else:
        auth_page()


main()
