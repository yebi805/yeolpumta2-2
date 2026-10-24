-- =====================================================================
--  열품타 픽셀 챌린지 · 데이터베이스 설정 파일 (처음 설치용)
-- ---------------------------------------------------------------------
--  사용법: Supabase 대시보드 > SQL Editor > New query 에
--          이 파일 전체를 붙여 넣고 [Run] 을 한 번 누르면 끝!
--
--  이 파일이 하는 일
--   1) 데이터를 저장할 표(테이블)를 만든다.
--   2) 앱이 부르는 "DB 함수(RPC)"를 만든다.
--      코인 지급·구매처럼 중요한 일은 전부 DB 함수 안에서
--      "한 번에 다 되거나, 하나도 안 되거나(트랜잭션)" 방식으로 처리한다.
--   3) 외부에서 표를 함부로 읽거나 쓰지 못하게 잠근다(RLS).
--      앱 서버(service_role 키)만 DB 함수를 부를 수 있다.
--
--  ※ 여러 번 실행해도 기존 데이터는 지워지지 않도록 작성했다.
-- =====================================================================

create extension if not exists pgcrypto;   -- gen_random_uuid() 사용


-- =====================================================================
-- 1. 테이블
-- =====================================================================

-- 학생 계정: 별명 + PIN(해시로만 저장, 원래 숫자는 저장하지 않음)
create table if not exists public.players (
  id             uuid primary key default gen_random_uuid(),
  nickname       text not null
                 check (nickname ~ '^[가-힣A-Za-z0-9_]{2,12}$'),  -- 한글/영문/숫자/_ 2~12자
  pin_salt       text not null,
  pin_hash       text not null,
  pin_iterations integer not null default 600000,
  created_at     timestamptz not null default now()
);
-- 대소문자만 다른 별명(Minsu / minsu)도 같은 별명으로 취급
create unique index if not exists players_nickname_lower_uq
  on public.players (lower(nickname));


-- 공부 시간 인증 제출 기록 (반려돼도 지우지 않고 기록으로 남김)
create table if not exists public.study_submissions (
  id               uuid primary key default gen_random_uuid(),
  player_id        uuid not null references public.players(id) on delete cascade,
  study_date       date not null,
  claimed_minutes  integer not null check (claimed_minutes between 1 and 960),   -- 학생 입력 (최대 16시간)
  approved_minutes integer check (approved_minutes between 1 and 960),            -- 관리자 승인 시간
  status           text not null default 'pending'
                   check (status in ('pending', 'approved', 'rejected')),
  reject_reason    text check (reject_reason is null or char_length(reject_reason) between 1 and 200),
  created_at       timestamptz not null default now(),
  reviewed_at      timestamptz,
  -- 상태와 나머지 값이 서로 어긋나지 않도록 강제
  constraint study_submissions_review_consistency check (
       (status = 'pending'  and approved_minutes is null     and reviewed_at is null)
    or (status = 'approved' and approved_minutes is not null and reviewed_at is not null)
    or (status = 'rejected' and approved_minutes is null     and reviewed_at is not null
                            and reject_reason is not null)
  )
);
-- ★ 핵심: 한 학생·한 날짜에 "검토 중" 또는 "승인" 기록은 딱 1개만 허용.
--   (반려된 기록은 여러 개 있어도 됨 → 반려 후 다시 제출 가능)
create unique index if not exists study_one_active_per_day
  on public.study_submissions (player_id, study_date)
  where status in ('pending', 'approved');
create index if not exists study_status_created_idx
  on public.study_submissions (status, created_at);


-- 코인 장부: 코인이 늘거나 줄 때마다 한 줄씩 기록 (잔액 = 전부 더한 값)
create table if not exists public.coin_ledger (
  id            bigint generated always as identity primary key,
  player_id     uuid not null references public.players(id) on delete cascade,
  event_key     text not null,          -- 예: attendance:2026-10-24 / study:2026-10-24:60 / purchase:crown
  amount        integer not null check (amount <> 0),
  reason        text not null,
  submission_id uuid references public.study_submissions(id) on delete set null,
  created_at    timestamptz not null default now(),
  -- ★ 핵심: 같은 학생에게 같은 이벤트 보상은 DB가 절대 두 번 넣지 않음
  unique (player_id, event_key)
);


-- 보유 아이템 (같은 아이템 두 번 구매 불가)
create table if not exists public.player_items (
  player_id  uuid not null references public.players(id) on delete cascade,
  item_id    text not null,
  price_paid integer not null check (price_paid > 0),
  bought_at  timestamptz not null default now(),
  primary key (player_id, item_id)
);


-- 장착 아이템 (부위별 1개, 그리고 "가진 아이템"만 장착 가능)
create table if not exists public.equipped_items (
  player_id uuid not null,
  category  text not null,
  item_id   text not null,
  primary key (player_id, category),
  foreign key (player_id, item_id)
    references public.player_items (player_id, item_id) on delete cascade
);


-- 앱 설정 (반 공동 목표 시간 등)
create table if not exists public.app_settings (
  key   text primary key,
  value text not null
);
insert into public.app_settings (key, value)
values ('class_goal_hours', '300')
on conflict (key) do nothing;


-- 로그인 실패 횟수 기록 (비밀번호 마구 찍기 방지)
create table if not exists public.login_guard (
  key          text primary key,       -- 'p:별명(소문자)' 또는 'admin'
  failed_count integer not null default 0,
  locked_until timestamptz,
  updated_at   timestamptz not null default now()
);


-- 코인 장부는 "추가만" 가능하게: 이미 쓴 줄을 고치지 못하게 막음
create or replace function public.coin_ledger_block_update()
returns trigger language plpgsql as $$
begin
  raise exception 'coin_ledger rows cannot be updated';
end $$;

drop trigger if exists coin_ledger_no_update on public.coin_ledger;
create trigger coin_ledger_no_update
  before update on public.coin_ledger
  for each row execute function public.coin_ledger_block_update();


-- =====================================================================
-- 2. 보안 잠금 (RLS)
--    RLS를 켜고 허용 규칙(policy)을 하나도 만들지 않으면
--    anon / authenticated 키로는 아무것도 읽고 쓸 수 없다.
--    service_role 키(앱 서버만 가짐)는 RLS를 통과한다.
-- =====================================================================
alter table public.players           enable row level security;
alter table public.study_submissions enable row level security;
alter table public.coin_ledger       enable row level security;
alter table public.player_items      enable row level security;
alter table public.equipped_items    enable row level security;
alter table public.app_settings      enable row level security;
alter table public.login_guard       enable row level security;

revoke all on table
  public.players, public.study_submissions, public.coin_ledger,
  public.player_items, public.equipped_items, public.app_settings,
  public.login_guard
from anon, authenticated;

-- 앱 서버(service_role)는 DB 함수를 통해 표를 사용할 수 있어야 한다.
-- (Supabase 기본 설정에도 들어 있지만, 확실하게 하기 위해 명시)
grant usage on schema public to service_role;
grant select, insert, update, delete on table
  public.players, public.study_submissions, public.coin_ledger,
  public.player_items, public.equipped_items, public.app_settings,
  public.login_guard
to service_role;
grant usage, select on all sequences in schema public to service_role;


-- =====================================================================
-- 3. DB 함수 (앱은 이 함수들만 호출한다)
--    결과는 대부분 {"ok": true/false, "code": "..."} 형태의 JSON.
-- =====================================================================

-- 한국 날짜 (서버가 어느 나라에 있든 한국 기준 "오늘")
create or replace function public.kst_today()
returns date language sql stable as $$
  select (now() at time zone 'Asia/Seoul')::date
$$;


-- ---------------------------------------------------------------------
-- 3-1. 계정
-- ---------------------------------------------------------------------
create or replace function public.create_player(
  p_nickname text, p_pin_salt text, p_pin_hash text, p_pin_iterations integer
) returns jsonb language plpgsql as $$
declare v_id uuid;
begin
  if p_nickname is null or p_nickname !~ '^[가-힣A-Za-z0-9_]{2,12}$' then
    return jsonb_build_object('ok', false, 'code', 'bad_nickname');
  end if;
  insert into public.players (nickname, pin_salt, pin_hash, pin_iterations)
  values (p_nickname, p_pin_salt, p_pin_hash, p_pin_iterations)
  returning id into v_id;
  return jsonb_build_object('ok', true, 'id', v_id);
exception when unique_violation then
  return jsonb_build_object('ok', false, 'code', 'nickname_taken');
end $$;


-- 로그인용: 별명으로 계정 찾기 (대소문자 무시)
create or replace function public.find_player_for_login(p_nickname text)
returns table (id uuid, nickname text, pin_salt text, pin_hash text, pin_iterations integer)
language sql stable as $$
  select p.id, p.nickname, p.pin_salt, p.pin_hash, p.pin_iterations
  from public.players p
  where lower(p.nickname) = lower(trim(p_nickname))
  limit 1
$$;


create or replace function public.get_player(p_player_id uuid)
returns table (id uuid, nickname text)
language sql stable as $$
  select p.id, p.nickname from public.players p where p.id = p_player_id
$$;


-- 로그인 잠금 상태 확인
create or replace function public.guard_status(p_key text)
returns jsonb language sql stable as $$
  select coalesce(
    (select jsonb_build_object(
              'locked', g.locked_until is not null and g.locked_until > now(),
              'seconds_left', greatest(0, ceil(extract(epoch from (g.locked_until - now()))))::int)
     from public.login_guard g where g.key = p_key),
    jsonb_build_object('locked', false, 'seconds_left', 0))
$$;


-- 로그인 결과 기록: 성공하면 초기화, p_max_fail번 연속 실패하면 p_lock_minutes분 잠금
create or replace function public.guard_record(
  p_key text, p_success boolean, p_max_fail integer default 5, p_lock_minutes integer default 10
) returns jsonb language plpgsql as $$
declare v_count integer;
begin
  if p_success then
    delete from public.login_guard where key = p_key;
    return jsonb_build_object('locked', false, 'seconds_left', 0);
  end if;

  insert into public.login_guard as g (key, failed_count, updated_at)
  values (p_key, 1, now())
  on conflict (key) do update
    set failed_count = case when g.locked_until is not null and g.locked_until <= now()
                            then 1 else g.failed_count + 1 end,
        locked_until = case when g.locked_until is not null and g.locked_until <= now()
                            then null else g.locked_until end,
        updated_at   = now()
  returning failed_count into v_count;

  if v_count >= p_max_fail then
    update public.login_guard
       set locked_until = now() + make_interval(mins => p_lock_minutes), failed_count = 0
     where key = p_key;
  end if;
  return public.guard_status(p_key);
end $$;


-- ---------------------------------------------------------------------
-- 3-2. 공부 시간 인증 제출 (학생)
-- ---------------------------------------------------------------------
--  서버(DB)에서 다시 검사하는 규칙
--   · 총 공부 시간 1분 ~ 960분(16시간)
--   · 날짜: 한국 기준 오늘 포함 최근 3일 (미래 날짜 불가)
--   · 같은 날짜에 검토 중/승인 기록이 있으면 제출 불가
create or replace function public.submit_study(
  p_player_id uuid, p_study_date date, p_minutes integer
) returns jsonb language plpgsql as $$
declare
  v_today date := public.kst_today();
  v_id    uuid;
begin
  if p_minutes is null or p_minutes < 1 then
    return jsonb_build_object('ok', false, 'code', 'zero_minutes');
  elsif p_minutes > 960 then
    return jsonb_build_object('ok', false, 'code', 'too_long');
  elsif p_study_date is null or p_study_date > v_today then
    return jsonb_build_object('ok', false, 'code', 'future_date');
  elsif p_study_date < v_today - 2 then
    return jsonb_build_object('ok', false, 'code', 'too_old');
  elsif not exists (select 1 from public.players where id = p_player_id) then
    return jsonb_build_object('ok', false, 'code', 'no_player');
  end if;

  insert into public.study_submissions (player_id, study_date, claimed_minutes)
  values (p_player_id, p_study_date, p_minutes)
  returning id into v_id;
  return jsonb_build_object('ok', true, 'id', v_id);
exception when unique_violation then
  return jsonb_build_object('ok', false, 'code', 'already_submitted');
end $$;


-- 내 제출 기록
create or replace function public.my_submissions(p_player_id uuid, p_limit integer default 30)
returns table (study_date date, claimed_minutes integer, approved_minutes integer,
               status text, reject_reason text, created_at timestamptz)
language sql stable as $$
  select s.study_date, s.claimed_minutes, s.approved_minutes, s.status, s.reject_reason, s.created_at
  from public.study_submissions s
  where s.player_id = p_player_id
  order by s.study_date desc, s.created_at desc
  limit greatest(1, least(p_limit, 200))
$$;


-- ---------------------------------------------------------------------
-- 3-3. 관리자: 검토 대기 목록 / 승인 / 반려
-- ---------------------------------------------------------------------
create or replace function public.pending_submissions()
returns table (id uuid, nickname text, study_date date, claimed_minutes integer,
               created_at timestamptz, rejected_before integer)
language sql stable as $$
  select s.id, p.nickname, s.study_date, s.claimed_minutes, s.created_at,
         (select count(*)::int from public.study_submissions r
           where r.player_id = s.player_id and r.study_date = s.study_date
             and r.status = 'rejected') as rejected_before
  from public.study_submissions s
  join public.players p on p.id = s.player_id
  where s.status = 'pending'
  order by s.study_date, s.created_at
$$;


create or replace function public.recent_reviews(p_limit integer default 30)
returns table (nickname text, study_date date, claimed_minutes integer, approved_minutes integer,
               status text, reject_reason text, reviewed_at timestamptz, coins integer)
language sql stable as $$
  select p.nickname, s.study_date, s.claimed_minutes, s.approved_minutes, s.status,
         s.reject_reason, s.reviewed_at,
         coalesce((select sum(l.amount)::int from public.coin_ledger l
                    where l.submission_id = s.id), 0) as coins
  from public.study_submissions s
  join public.players p on p.id = s.player_id
  where s.status <> 'pending'
  order by s.reviewed_at desc
  limit greatest(1, least(p_limit, 200))
$$;


--  승인 + 보상 지급 (한 트랜잭션)
--   p_rules 예시 (app.py 의 REWARD_RULES 가 그대로 넘어옴):
--   {"attendance": 10,
--    "milestones": [{"minutes": 60, "coins": 10},
--                   {"minutes": 120, "coins": 10},
--                   {"minutes": 180, "coins": 15}]}
--
--  안전장치
--   · FOR UPDATE 로 제출 행을 잠가서 동시에 두 번 승인해도 한 번만 처리
--   · 이미 승인/반려된 건은 'already_reviewed' 로 끝 (코인 지급 없음)
--   · 보상은 (학생, event_key) 고유 제약 + ON CONFLICT DO NOTHING 으로 중복 불가
--   · 중간에 오류가 나면 상태 변경과 코인 지급이 모두 취소됨(롤백)
create or replace function public.approve_submission(
  p_submission_id uuid, p_approved_minutes integer, p_rules jsonb
) returns jsonb language plpgsql as $$
declare
  s          public.study_submissions%rowtype;
  v_att      integer;
  v_rule     jsonb;
  v_min      integer;
  v_coins    integer;
  v_rows     integer;
  v_total    integer := 0;
  v_details  jsonb := '[]'::jsonb;
begin
  -- (1) 입력 검사
  if p_approved_minutes is null or p_approved_minutes < 1 or p_approved_minutes > 960 then
    return jsonb_build_object('ok', false, 'code', 'bad_minutes');
  end if;
  v_att := (p_rules ->> 'attendance')::int;
  if v_att is null or v_att < 0 or v_att > 1000
     or jsonb_typeof(p_rules -> 'milestones') is distinct from 'array' then
    raise exception 'invalid reward rules: %', p_rules;
  end if;

  -- (2) 제출 행 잠금 + 상태 확인
  select * into s from public.study_submissions where id = p_submission_id for update;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'not_found');
  end if;
  if s.status <> 'pending' then
    return jsonb_build_object('ok', false, 'code', 'already_reviewed', 'status', s.status);
  end if;

  -- (3) 승인 처리
  update public.study_submissions
     set status = 'approved', approved_minutes = p_approved_minutes, reviewed_at = now()
   where id = s.id;

  -- (4) 출석 보상
  if v_att > 0 then
    insert into public.coin_ledger (player_id, event_key, amount, reason, submission_id)
    values (s.player_id, 'attendance:' || s.study_date, v_att,
            to_char(s.study_date, 'MM/DD') || ' 출석 인증', s.id)
    on conflict (player_id, event_key) do nothing;
    get diagnostics v_rows = row_count;
    if v_rows > 0 then
      v_total := v_total + v_att;
      v_details := v_details || jsonb_build_object('reason', '출석', 'coins', v_att);
    end if;
  end if;

  -- (5) 공부 시간 달성 보상 (달성한 기준을 모두 합산)
  for v_rule in select * from jsonb_array_elements(p_rules -> 'milestones') loop
    v_min   := (v_rule ->> 'minutes')::int;
    v_coins := (v_rule ->> 'coins')::int;
    if v_min is null or v_min < 1 or v_min > 960 or v_coins is null or v_coins < 0 or v_coins > 1000 then
      raise exception 'invalid milestone rule: %', v_rule;
    end if;
    if p_approved_minutes >= v_min and v_coins > 0 then
      insert into public.coin_ledger (player_id, event_key, amount, reason, submission_id)
      values (s.player_id, 'study:' || s.study_date || ':' || v_min, v_coins,
              to_char(s.study_date, 'MM/DD') || ' ' ||
                case when v_min % 60 = 0 then (v_min / 60) || '시간'
                     else v_min || '분' end || ' 달성', s.id)
      on conflict (player_id, event_key) do nothing;
      get diagnostics v_rows = row_count;
      if v_rows > 0 then
        v_total := v_total + v_coins;
        v_details := v_details || jsonb_build_object('reason', v_min || '분 달성', 'coins', v_coins);
      end if;
    end if;
  end loop;

  return jsonb_build_object('ok', true, 'coins_granted', v_total, 'details', v_details);
end $$;


create or replace function public.reject_submission(p_submission_id uuid, p_reason text)
returns jsonb language plpgsql as $$
declare
  s        public.study_submissions%rowtype;
  v_reason text := nullif(trim(coalesce(p_reason, '')), '');
begin
  if v_reason is null then
    return jsonb_build_object('ok', false, 'code', 'no_reason');
  elsif char_length(v_reason) > 200 then
    return jsonb_build_object('ok', false, 'code', 'reason_too_long');
  end if;

  select * into s from public.study_submissions where id = p_submission_id for update;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'not_found');
  end if;
  if s.status <> 'pending' then
    return jsonb_build_object('ok', false, 'code', 'already_reviewed', 'status', s.status);
  end if;

  update public.study_submissions
     set status = 'rejected', reject_reason = v_reason, reviewed_at = now()
   where id = s.id;
  return jsonb_build_object('ok', true);
end $$;


-- ---------------------------------------------------------------------
-- 3-4. 코인 / 상점 / 장착
-- ---------------------------------------------------------------------
create or replace function public.player_balance(p_player_id uuid)
returns integer language sql stable as $$
  select coalesce(sum(amount), 0)::int from public.coin_ledger where player_id = p_player_id
$$;


create or replace function public.coin_history(p_player_id uuid, p_limit integer default 20)
returns table (amount integer, reason text, created_at timestamptz)
language sql stable as $$
  select l.amount, l.reason, l.created_at
  from public.coin_ledger l
  where l.player_id = p_player_id
  order by l.created_at desc, l.id desc
  limit greatest(1, least(p_limit, 200))
$$;


--  구매 (한 트랜잭션)
--   · 학생 행을 FOR UPDATE 로 잠가서, 같은 학생의 구매 요청이 동시에 와도 하나씩 처리
--   · 이미 보유 → 'already_owned', 잔액 부족 → 'not_enough'
--   · 아이템 지급과 코인 차감이 함께 성공하거나 함께 취소됨
create or replace function public.purchase_item(
  p_player_id uuid, p_item_id text, p_item_name text, p_price integer
) returns jsonb language plpgsql as $$
declare v_balance integer;
begin
  if p_price is null or p_price < 1 or p_price > 100000
     or p_item_id is null or p_item_id !~ '^[a-z0-9_]{1,40}$' then
    raise exception 'invalid item: % / %', p_item_id, p_price;
  end if;

  perform 1 from public.players where id = p_player_id for update;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'no_player');
  end if;

  if exists (select 1 from public.player_items
              where player_id = p_player_id and item_id = p_item_id) then
    return jsonb_build_object('ok', false, 'code', 'already_owned');
  end if;

  v_balance := public.player_balance(p_player_id);
  if v_balance < p_price then
    return jsonb_build_object('ok', false, 'code', 'not_enough', 'balance', v_balance);
  end if;

  insert into public.player_items (player_id, item_id, price_paid)
  values (p_player_id, p_item_id, p_price);

  insert into public.coin_ledger (player_id, event_key, amount, reason)
  values (p_player_id, 'purchase:' || p_item_id, -p_price,
          '아이템 구매: ' || coalesce(nullif(trim(p_item_name), ''), p_item_id));

  return jsonb_build_object('ok', true, 'balance', v_balance - p_price);
end $$;


create or replace function public.player_inventory(p_player_id uuid)
returns jsonb language sql stable as $$
  select jsonb_build_object(
    'owned', coalesce((select jsonb_agg(item_id order by bought_at)
                         from public.player_items where player_id = p_player_id), '[]'::jsonb),
    'equipped', coalesce((select jsonb_object_agg(category, item_id)
                            from public.equipped_items where player_id = p_player_id), '{}'::jsonb))
$$;


-- 장착 / 해제 (p_item_id 가 null 이면 해당 부위 해제)
create or replace function public.equip_item(p_player_id uuid, p_category text, p_item_id text)
returns jsonb language plpgsql as $$
begin
  if p_category is null or char_length(p_category) not between 1 and 20 then
    raise exception 'invalid category';
  end if;

  if p_item_id is null then
    delete from public.equipped_items where player_id = p_player_id and category = p_category;
    return jsonb_build_object('ok', true);
  end if;

  if not exists (select 1 from public.player_items
                  where player_id = p_player_id and item_id = p_item_id) then
    return jsonb_build_object('ok', false, 'code', 'not_owned');
  end if;

  insert into public.equipped_items (player_id, category, item_id)
  values (p_player_id, p_category, p_item_id)
  on conflict (player_id, category) do update set item_id = excluded.item_id;
  return jsonb_build_object('ok', true);
end $$;


-- ---------------------------------------------------------------------
-- 3-5. 순위 / 반 공동 퀘스트 (승인된 시간만 합산)
-- ---------------------------------------------------------------------
create or replace function public.leaderboard()
returns table (nickname text, total_minutes integer, study_days integer)
language sql stable as $$
  select p.nickname,
         coalesce(sum(s.approved_minutes), 0)::int as total_minutes,
         count(s.id)::int as study_days
  from public.players p
  left join public.study_submissions s
         on s.player_id = p.id and s.status = 'approved'
  group by p.id, p.nickname
  order by total_minutes desc, study_days desc, p.nickname
$$;


create or replace function public.class_progress()
returns jsonb language sql stable as $$
  select jsonb_build_object(
    'total_minutes', coalesce((select sum(approved_minutes)
                                 from public.study_submissions where status = 'approved'), 0)::int,
    'goal_hours', coalesce((select value::int from public.app_settings
                             where key = 'class_goal_hours'), 300),
    'players', (select count(*) from public.players)::int,
    'contributors', (select count(distinct player_id)
                       from public.study_submissions where status = 'approved')::int)
$$;


create or replace function public.set_class_goal(p_hours integer)
returns jsonb language plpgsql as $$
begin
  if p_hours is null or p_hours < 1 or p_hours > 100000 then
    return jsonb_build_object('ok', false, 'code', 'bad_goal');
  end if;
  insert into public.app_settings (key, value) values ('class_goal_hours', p_hours::text)
  on conflict (key) do update set value = excluded.value;
  return jsonb_build_object('ok', true);
end $$;


-- =====================================================================
-- 4. 함수 실행 권한: 앱 서버(service_role)만 허용
-- =====================================================================
do $$
declare f record;
begin
  for f in
    select p.oid::regprocedure as sig
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.proname in (
        'kst_today', 'create_player', 'find_player_for_login', 'get_player',
        'guard_status', 'guard_record', 'submit_study', 'my_submissions',
        'pending_submissions', 'recent_reviews', 'approve_submission',
        'reject_submission', 'player_balance', 'coin_history', 'purchase_item',
        'player_inventory', 'equip_item', 'leaderboard', 'class_progress',
        'set_class_goal', 'coin_ledger_block_update')
  loop
    execute format('revoke all on function %s from public, anon, authenticated', f.sig);
    execute format('grant execute on function %s to service_role', f.sig);
  end loop;
end $$;

-- 끝! 성공하면 아래쪽에 "Success. No rows returned" 가 보인다.
