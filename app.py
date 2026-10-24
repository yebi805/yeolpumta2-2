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

# 상점 아이템 (id 는 영어 소문자/숫자/_ 만, 한 번 정하면 바꾸지 않기)
CATEGORIES = ["모자", "얼굴", "옷", "장식"]
ITEMS = [
    {"id": "cap_blue", "name": "파란 모자",   "category": "모자", "price": 30,  "rarity": "일반"},
    {"id": "glasses",  "name": "동그란 안경", "category": "얼굴", "price": 40,  "rarity": "일반"},
    {"id": "hoodie",   "name": "민트 후드",   "category": "옷",   "price": 60,  "rarity": "희귀"},
    {"id": "star",     "name": "반짝 별",     "category": "장식", "price": 80,  "rarity": "희귀"},
    {"id": "crown",    "name": "픽셀 왕관",   "category": "모자", "price": 150, "rarity": "에픽"},
    {"id": "book",     "name": "공부 책",     "category": "장식", "price": 25,  "rarity": "일반"},
]
ITEM_BY_ID = {item["id"]: item for item in ITEMS}

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
def get_db():
    url = get_secret("SUPABASE_URL")
    # 새 방식 secret key(sb_secret_...) 또는 예전 방식 service_role key 둘 다 지원
    key = get_secret("SUPABASE_SECRET_KEY") or get_secret("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        return None
    return create_client(url, key)


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
}

# 겹쳐 그리는 순서 (뒤쪽 → 앞쪽)
LAYER_ORDER = ["옷", "얼굴", "모자", "장식"]


def avatar_svg(equipped: dict, px: int = 10) -> str:
    grid = [list(row) for row in BASE_SPRITE]
    for category in LAYER_ORDER:
        item_id = equipped.get(category)
        for row_idx, row in ITEM_SPRITES.get(item_id, {}).items():
            for col_idx, ch in enumerate(row):
                if ch != ".":
                    grid[row_idx][col_idx] = ch
    rects = []
    for y, row in enumerate(grid):
        for x, ch in enumerate(row):
            if ch in PALETTE:
                rects.append(f'<rect x="{x}" y="{y}" width="1" height="1" fill="{PALETTE[ch]}"/>')
    w, h = 16, len(grid)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w * px}" '
            f'height="{h * px}" shape-rendering="crispEdges" role="img" aria-label="픽셀 캐릭터">'
            + "".join(rects) + "</svg>")


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

    tabs = st.tabs(["🏠 홈", "✏️ 인증", "🧍 캐릭터", "🛍️ 상점", "🏅 순위", "🤝 퀘스트"])
    with tabs[0]:
        home_tab(player_id, nickname, coins, owned, equipped, submissions)
    with tabs[1]:
        submit_tab(player_id, submissions)
    with tabs[2]:
        character_tab(player_id, nickname, owned, equipped)
    with tabs[3]:
        shop_tab(player_id, coins, owned, equipped)
    with tabs[4]:
        ranking_tab(nickname)
    with tabs[5]:
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
    <div class="px-label" style="margin-top:6px">보유 아이템 {len(owned)} / {len(ITEMS)}</div>
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
        choices = [NONE] + [i["id"] for i in ITEMS if i["category"] == category and i["id"] in owned]
        current = equipped.get(category) if equipped.get(category) in choices else NONE
        picked = st.selectbox(
            category, choices, index=choices.index(current),
            format_func=lambda x: "착용 안 함" if x == NONE else ITEM_BY_ID[x]["name"],
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
        flash("success", "👕 착용 상태를 저장했어!")
        st.rerun()


def shop_tab(player_id, coins, owned, equipped):
    st.markdown(f"#### 🛍️ 아이템 상점 · 내 코인 🪙 {int(coins)}")
    st.caption("아이템은 한 번만 살 수 있고, 산 뒤에는 🧍 캐릭터 탭에서 착용해.")
    cols = st.columns(2)
    for idx, item in enumerate(ITEMS):
        with cols[idx % 2]:
            with st.container(border=True):
                preview = dict(equipped)
                preview[item["category"]] = item["id"]
                st.markdown(
                    f"<div style='text-align:center'><div class='px-avatar'>{avatar_svg(preview, 5)}</div>"
                    f"<div class='px-font' style='margin-top:6px'>{esc(item['name'])}</div>"
                    f"<span class='px-badge'>{esc(item['category'])}</span>"
                    f"<span class='px-badge'>{esc(item['rarity'])}</span>"
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
    elif res.get("code") == "not_enough":
        st.error(f"코인이 부족해. (현재 🪙 {res.get('balance', 0)})")
    else:
        st.error("구매하지 못했어. 다시 로그인해 줘.")


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
    t1, t2, t3 = st.tabs([f"📋 검토 대기 ({len(pending)})", "🗂️ 처리 내역", "⚙️ 반 설정·현황"])
    with t1:
        admin_review(pending)
    with t2:
        admin_history()
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


def admin_settings():
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
        st.error("데이터베이스 연결 정보가 없어요. README 의 '3단계: Secrets 입력'을 따라 "
                 "SUPABASE_URL 과 SUPABASE_SECRET_KEY 를 넣어 주세요.")
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
