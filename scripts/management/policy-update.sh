#!/usr/bin/env bash
# Edits the live Authelia access-control rules and user group memberships.
#
# Every change is backed up first, validated afterwards and rolled back if
# validation fails. Values reach yq only through the environment
# (strenv/from_json), never through the expression text.
set -Eeuo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

POLICY_BACKUP_DIR="${POLICY_BACKUP_DIR:-$ZTVPN_BACKUP_DIR/policy}"
# auto: docker if usable, else structural checks only | docker | yq
AUTHELIA_VALIDATE="${AUTHELIA_VALIDATE:-auto}"

usage() {
    cat <<EOF
Usage: $(basename "$0") <command> [options]

Works on the live Authelia configuration:
  config:   $AUTHELIA_CONFIG
  users DB: $AUTHELIA_USERS_DB

Access-control rules:
  list-rules [--json]
  add-rule --domain D --policy one_factor|two_factor|deny
           [--subject group:G|user:U ...] [--network NAME|CIDR ...]
           [--resource REGEX ...] [--position N]
           Subjects are OR-ed. Rules are evaluated top-down; default is to append.
  remove-rule --index N | --domain D
           --domain removes D from every rule; rules left without a domain are deleted.

Group membership (file backend; groups must be in KNOWN_GROUPS):
  set-groups <user> g1,g2 [--exact]
           Without --exact the user keeps the default groups ($DEFAULT_USER_GROUPS)
           they already have.
  add-group <user> <group>
  remove-group <user> <group>

Maintenance:
  validate               Check config and users DB (docker validate-config if available)
  backup                 Copy config and users DB to $POLICY_BACKUP_DIR/<timestamp>
  restore <backup>       Restore a backup (name or path under $POLICY_BACKUP_DIR)

Global options:
  --restart              Restart Authelia (compose service $AUTHELIA_SERVICE) after a
                         successful config change (Authelia does not reload
                         configuration.yml by itself; the users DB is reloaded
                         when "watch: true" is set)
  -h, --help

Known groups: $KNOWN_GROUPS
EOF
}

COMMAND="${1:-}"
[[ -n "$COMMAND" ]] || { usage >&2; exit 1; }
shift
case "$COMMAND" in
    -h|--help|help) usage; exit 0 ;;
    list-rules|add-rule|remove-rule|set-groups|add-group|remove-group|validate|backup|restore) ;;
    *) die "Unknown command: $COMMAND (see --help)" ;;
esac

DOMAIN_ARG="" POLICY="" POSITION="" INDEX="" EXACT=0 JSON=0 RESTART=0
SUBJECTS=() NETWORKS=() RESOURCES=() ARGS=()
while (($#)); do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --domain)   need_value "$@"; DOMAIN_ARG="$2"; shift 2 ;;
        --policy)   need_value "$@"; POLICY="$2"; shift 2 ;;
        --subject)  need_value "$@"; SUBJECTS+=("$2"); shift 2 ;;
        --network)  need_value "$@"; NETWORKS+=("$2"); shift 2 ;;
        --resource) need_value "$@"; RESOURCES+=("$2"); shift 2 ;;
        --position) need_value "$@"; POSITION="$2"; shift 2 ;;
        --index)    need_value "$@"; INDEX="$2"; shift 2 ;;
        --exact)    EXACT=1; shift ;;
        --json)     JSON=1; shift ;;
        --restart)  RESTART=1; shift ;;
        --) shift; ARGS+=("$@"); break ;;
        -*) die "Unknown option: $1 (see --help)" ;;
        *) ARGS+=("$1"); shift ;;
    esac
done

require_cmd jq yq
require_yq || exit 1

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

check_username() {
    validate_username "$1" && [[ "$1" != *--* ]] || die "Invalid username: $1"
}

require_file_backend() {
    [[ "$AUTHELIA_BACKEND" == file ]] ||
        die "AUTHELIA_BACKEND=$AUTHELIA_BACKEND: group membership is managed in the directory, not here"
    [[ -f "$AUTHELIA_USERS_DB" ]] || die "Users database $AUTHELIA_USERS_DB not found"
}

require_config() {
    [[ -f "$AUTHELIA_CONFIG" ]] || die "Authelia configuration $AUTHELIA_CONFIG not found"
}

rules_json() {
    yq -o=json -I0 '.access_control.rules // []' "$AUTHELIA_CONFIG"
}

# Applies a constant yq expression to a file in place (atomically, same mode).
# Values must be passed via the environment.
yq_edit() {
    local expr="$1" file="$2" mode out
    mode="$(stat -c %a "$file")"
    out="$(yq "$expr" "$file")" || return 1
    printf '%s\n' "$out" | atomic_write "$file" "$mode"
}

# Copies the current config and users DB; prints the backup directory.
make_backup() {
    local dir f
    dir="$POLICY_BACKUP_DIR/$(date +%Y%m%dT%H%M%S.%N)"
    (umask 077; mkdir -p "$dir") || return 1
    chmod 700 "$POLICY_BACKUP_DIR"
    for f in "$AUTHELIA_CONFIG" "$AUTHELIA_USERS_DB"; do
        [[ -f "$f" ]] && cp -p "$f" "$dir/$(basename "$f")"
    done
    printf '%s\n' "$dir"
}

restore_from() {
    local dir="$1" f dest mode rc=0
    for f in "$AUTHELIA_CONFIG" "$AUTHELIA_USERS_DB"; do
        [[ -f "$dir/$(basename "$f")" ]] || continue
        dest="$f"
        mode="$(stat -c %a "$dir/$(basename "$f")")"
        mkdir -p "$(dirname "$dest")"
        atomic_write "$dest" "$mode" <"$dir/$(basename "$f")" || rc=1
    done
    return "$rc"
}

# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

# Structural checks that do not need Authelia itself.
check_config_structure() {
    local errors=0 net_names rules
    if ! yq -e '.' "$AUTHELIA_CONFIG" >/dev/null 2>&1; then
        error "$AUTHELIA_CONFIG is not valid YAML"
        return 1
    fi
    if ! yq -e '(.access_control | type) == "!!map"' "$AUTHELIA_CONFIG" >/dev/null 2>&1; then
        error "No access_control section in $AUTHELIA_CONFIG"
        return 1
    fi
    net_names="$(yq -o=json -I0 '[(.access_control.networks // [])[] | .name]' "$AUTHELIA_CONFIG")"
    rules="$(rules_json)"
    local problems
    problems="$(jq -r --argjson nets "$net_names" --arg known "$KNOWN_GROUPS" '
        ($known | split(",")) as $groups |
        if type != "array" then "access_control.rules is not a list" else
        to_entries[] | .key as $i | .value as $r |
        (if ($r.domain // $r.domain_regex) == null then "rule \($i): no domain" else empty end),
        (if ($r.policy | IN("bypass", "one_factor", "two_factor", "deny")) then empty
         else "rule \($i): invalid policy \($r.policy)" end),
        (($r.networks // []) | if type == "array" then .[] else . end
         | select((. as $n | $nets | index($n)) == null and (test("^[0-9.]+(/[0-9]+)?$") | not))
         | "rule \($i): unknown network \(.)"),
        (($r.subject // []) | if type == "array" then .[] else . end | if type == "array" then .[] else . end
         | select(startswith("group:")) | ltrimstr("group:")
         | select(. as $g | $groups | index($g) == null)
         | "WARN rule \($i): group \(.) is not in KNOWN_GROUPS")
        end' <<<"$rules")" || { error "Could not inspect rules"; return 1; }
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        if [[ "$line" == WARN* ]]; then
            warn "${line#WARN }"
        else
            error "$line"
            errors=$((errors + 1))
        fi
    done <<<"$problems"
    ((errors == 0))
}

check_users_db() {
    [[ "$AUTHELIA_BACKEND" == file ]] || return 0
    [[ -f "$AUTHELIA_USERS_DB" ]] || { warn "No users database at $AUTHELIA_USERS_DB"; return 0; }
    local users problems line errors=0
    users="$(yq -o=json -I0 '.users' "$AUTHELIA_USERS_DB" 2>/dev/null)" || {
        error "$AUTHELIA_USERS_DB is not valid YAML"
        return 1
    }
    problems="$(jq -r --arg known "$KNOWN_GROUPS" '
        ($known | split(",")) as $groups |
        if type != "object" then "users is not a map" else
        to_entries[] | .key as $u | .value as $v |
        (if ($v.password | type) != "string" or ($v.password | startswith("$argon2id$") | not)
         then "user \($u): password is not an argon2id hash" else empty end),
        (if ($v.groups // [] | type) != "array" then "user \($u): groups is not a list"
         else ($v.groups // [])[] | select(. as $g | $groups | index($g) == null)
              | "WARN user \($u): group \(.) is not in KNOWN_GROUPS" end)
        end' <<<"$users")" || { error "Could not inspect $AUTHELIA_USERS_DB"; return 1; }
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        if [[ "$line" == WARN* ]]; then warn "${line#WARN }"; else error "$line"; errors=$((errors + 1)); fi
    done <<<"$problems"
    ((errors == 0))
}

docker_usable() {
    case "$AUTHELIA_VALIDATE" in
        yq) return 1 ;;
        docker) require_cmd docker; return 0 ;;
        auto) command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 ;;
        *) die "Invalid AUTHELIA_VALIDATE: $AUTHELIA_VALIDATE (auto, docker, yq)" ;;
    esac
}

# Runs "authelia validate-config" against the live directory with the same
# environment docker-compose gives the container (see authelia-setup.sh):
# template filter for {{ env "DOMAIN" }} and secrets as *_FILE under /secrets.
docker_validate() {
    local -a args=(run --rm --network none -v "$AUTHELIA_DIR:/config:ro"
        -e "DOMAIN=$DOMAIN" -e "AUTH_DOMAIN=$AUTH_DOMAIN"
        -e "VPN_SUBNET=$VPN_SUBNET" -e "SERVICES_SUBNET=$SERVICES_SUBNET")
    grep -q '{{' "$AUTHELIA_CONFIG" && args+=(-e X_AUTHELIA_CONFIG_FILTERS=template)
    if [[ -d "$AUTHELIA_SECRETS_DIR" ]]; then
        args+=(-v "$AUTHELIA_SECRETS_DIR:/secrets:ro")
        local var file
        while read -r var file; do
            [[ -f "$AUTHELIA_SECRETS_DIR/$file" ]] && args+=(-e "${var}_FILE=/secrets/$file")
        done <<'LIST'
AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET jwt_secret
AUTHELIA_SESSION_SECRET session_secret
AUTHELIA_STORAGE_ENCRYPTION_KEY storage_encryption_key
AUTHELIA_STORAGE_POSTGRES_PASSWORD postgres_password
AUTHELIA_SESSION_REDIS_PASSWORD redis_password
AUTHELIA_NOTIFIER_SMTP_PASSWORD smtp_password
LIST
    fi
    docker "${args[@]}" "$AUTHELIA_IMAGE" \
        authelia validate-config --config "/config/$(basename "$AUTHELIA_CONFIG")" >&2
}

# Set by begin_change: did docker validation pass before the change?
BASELINE_DOCKER=""

validate_all() {
    local ok=0
    if [[ -f "$AUTHELIA_CONFIG" ]]; then
        check_config_structure || ok=1
    else
        error "Authelia configuration $AUTHELIA_CONFIG not found"
        ok=1
    fi
    check_users_db || ok=1
    ((ok == 0)) || return 1
    if [[ -f "$AUTHELIA_CONFIG" ]] && docker_usable; then
        if docker_validate; then
            info "authelia validate-config passed"
        elif [[ "$BASELINE_DOCKER" == failed ]]; then
            warn "authelia validate-config also failed before this change; only structural checks apply"
        else
            error "authelia validate-config failed"
            return 1
        fi
    else
        info "Structural checks passed (Authelia validation not available, AUTHELIA_VALIDATE=$AUTHELIA_VALIDATE)"
    fi
}

BACKUP=""
begin_change() {
    ztvpn_lock policy
    ztvpn_lock users
    BACKUP="$(make_backup)" || die "Could not create a backup; nothing changed"
    info "Backup: $BACKUP"
    if [[ -f "$AUTHELIA_CONFIG" ]] && docker_usable; then
        if docker_validate 2>/dev/null; then
            BASELINE_DOCKER=passed
        else
            BASELINE_DOCKER=failed
            warn "The current configuration does not pass authelia validate-config"
        fi
    fi
}

finish_change() {
    local what="$1"
    if validate_all; then
        audit policy-update "$what result=ok backup=$BACKUP"
        success "$what"
        return 0
    fi
    if restore_from "$BACKUP"; then
        audit policy-update "$what result=rolled-back backup=$BACKUP"
        die "Validation failed; restored the previous files from $BACKUP"
    fi
    die "Validation failed AND restoring $BACKUP failed; restore it manually"
}

maybe_restart() {
    if ((RESTART)); then
        require_cmd docker
        if [[ -n "$AUTHELIA_CONTAINER" ]]; then
            [[ "$AUTHELIA_CONTAINER" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "Invalid AUTHELIA_CONTAINER"
            docker restart "$AUTHELIA_CONTAINER" >/dev/null || die "Could not restart $AUTHELIA_CONTAINER"
            success "Restarted $AUTHELIA_CONTAINER"
        else
            [[ -f "$COMPOSE_FILE_PATH" ]] || die "No compose file at $COMPOSE_FILE_PATH; set AUTHELIA_CONTAINER"
            docker compose -f "$COMPOSE_FILE_PATH" restart "$AUTHELIA_SERVICE" >/dev/null ||
                die "Could not restart compose service $AUTHELIA_SERVICE"
            success "Restarted compose service $AUTHELIA_SERVICE"
        fi
    else
        info "Restart Authelia to apply configuration changes (or pass --restart)"
    fi
}

# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------

cmd_list_rules() {
    require_config
    if ((JSON)); then
        rules_json | jq .
        return 0
    fi
    rules_json | jq -r '
        def csv: if . == null then "-" elif type == "array" then map(if type == "array" then join("&") else tostring end) | join(",") else tostring end;
        (["INDEX", "DOMAIN", "POLICY", "SUBJECT", "NETWORKS", "RESOURCES"] | @tsv),
        (to_entries[] | [(.key | tostring), (.value.domain // .value.domain_regex | csv), (.value.policy // "-"),
            (.value.subject | csv), (.value.networks | csv), (.value.resources | csv)] | @tsv)'
}

validate_domain() {
    [[ "$1" =~ ^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] && ((${#1} <= 253))
}

cmd_add_rule() {
    require_root
    require_config
    ((${#ARGS[@]} == 0)) || die "Unexpected argument: ${ARGS[0]}"
    [[ -n "$DOMAIN_ARG" ]] || die "--domain is required"
    DOMAIN_ARG="${DOMAIN_ARG,,}"
    validate_domain "$DOMAIN_ARG" || die "Invalid domain: $DOMAIN_ARG"
    case "$POLICY" in
        one_factor|two_factor|deny) ;;
        "") die "--policy is required" ;;
        *) die "Invalid policy: $POLICY (one_factor, two_factor, deny)" ;;
    esac

    local s n r
    for s in "${SUBJECTS[@]}"; do
        case "$s" in
            group:*) is_known_group "${s#group:}" || die "Unknown group in subject: ${s#group:} (allowed: $KNOWN_GROUPS)" ;;
            user:*)  check_username "${s#user:}" ;;
            *) die "Invalid subject: $s (use group:<name> or user:<name>)" ;;
        esac
    done
    local nets
    nets="$(yq -o=json -I0 '[(.access_control.networks // [])[] | .name]' "$AUTHELIA_CONFIG")"
    for n in "${NETWORKS[@]}"; do
        if validate_cidr "$n" || validate_ipv4 "$n"; then continue; fi
        jq -e --arg n "$n" 'index($n) != null' <<<"$nets" >/dev/null ||
            die "Unknown network: $n (defined: $(jq -r 'join(", ")' <<<"$nets"))"
    done
    for r in "${RESOURCES[@]}"; do
        [[ ${#r} -le 512 && "$r" =~ ^[[:print:]]+$ ]] || die "Invalid resource pattern"
        jq -n --arg r "$r" '"" | test($r)' >/dev/null 2>&1 || die "Resource is not a valid regular expression: $r"
    done

    local count
    count="$(rules_json | jq 'length')"
    if [[ -z "$POSITION" ]]; then
        POSITION="$count"
    else
        [[ "$POSITION" =~ ^[0-9]+$ ]] && ((POSITION <= count)) || die "Invalid --position (0..$count)"
    fi

    local rule
    rule="$(jq -cn --arg d "$DOMAIN_ARG" --arg p "$POLICY" '{domain: $d, policy: $p}')"
    # Lists are added one by one so that every value stays a --arg.
    if ((${#SUBJECTS[@]})); then
        rule="$(jq -c '.subject = $ARGS.positional' --args "${SUBJECTS[@]}" <<<"$rule")"
    fi
    if ((${#NETWORKS[@]})); then
        rule="$(jq -c '.networks = $ARGS.positional' --args "${NETWORKS[@]}" <<<"$rule")"
    fi
    if ((${#RESOURCES[@]})); then
        rule="$(jq -c '.resources = $ARGS.positional' --args "${RESOURCES[@]}" <<<"$rule")"
    fi

    begin_change
    R="$rule" P="$POSITION" yq_edit '.access_control.rules = (.access_control.rules // []) |
        .access_control.rules |= (.[:env(P)] + [strenv(R) | from_json | ... style=""] + .[env(P):])' \
        "$AUTHELIA_CONFIG" || { restore_from "$BACKUP"; die "Could not write $AUTHELIA_CONFIG"; }
    finish_change "Added rule #$POSITION: $DOMAIN_ARG -> $POLICY"
    maybe_restart
}

cmd_remove_rule() {
    require_root
    require_config
    ((${#ARGS[@]} == 0)) || die "Unexpected argument: ${ARGS[0]}"
    [[ -n "$INDEX" && -z "$DOMAIN_ARG" || -z "$INDEX" && -n "$DOMAIN_ARG" ]] ||
        die "Give exactly one of --index or --domain"
    local rules count
    rules="$(rules_json)"
    count="$(jq 'length' <<<"$rules")"

    if [[ -n "$INDEX" ]]; then
        [[ "$INDEX" =~ ^[0-9]+$ ]] && ((INDEX < count)) || die "No rule with index $INDEX (0..$((count - 1)))"
        begin_change
        I="$INDEX" yq_edit 'del(.access_control.rules[env(I)])' "$AUTHELIA_CONFIG" ||
            { restore_from "$BACKUP"; die "Could not write $AUTHELIA_CONFIG"; }
        finish_change "Removed rule #$INDEX"
        maybe_restart
        return 0
    fi

    DOMAIN_ARG="${DOMAIN_ARG,,}"
    validate_domain "$DOMAIN_ARG" || die "Invalid domain: $DOMAIN_ARG"
    # "del <i>" for rules that only cover this domain, "trim <i>" for rules
    # that list it among others. Highest index first so indices stay valid.
    local plan
    # Domains in the shipped config are templates ('app.{{ env "DOMAIN" }}');
    # they match both literally and after expansion.
    plan="$(jq -r --arg d "$DOMAIN_ARG" --arg dom "$DOMAIN" --arg auth "$AUTH_DOMAIN" '
        def expand: gsub("\\{\\{ *env +\"AUTH_DOMAIN\" *\\}\\}"; $auth) | gsub("\\{\\{ *env +\"DOMAIN\" *\\}\\}"; $dom);
        def hit: . == $d or (expand == $d);
        def doms: if type == "array" then . else [.] end;
        to_entries | reverse[] | .key as $i | (.value.domain // null) as $v |
        if $v == null then empty
        elif ($v | doms | all(hit)) then "del \($i)"
        elif ($v | doms | any(hit)) then ($v | doms | map(select(hit)) | .[] | "trim \($i) \(.)")
        else empty end' <<<"$rules")"
    [[ -n "$plan" ]] || die "No rule for domain $DOMAIN_ARG"

    begin_change
    local op idx value n=0
    while read -r op idx value; do
        case "$op" in
            del)  I="$idx" yq_edit 'del(.access_control.rules[env(I)])' "$AUTHELIA_CONFIG" ;;
            trim) I="$idx" D="$value" yq_edit '.access_control.rules[env(I)].domain |= (. - [strenv(D)])' "$AUTHELIA_CONFIG" ;;
        esac || { restore_from "$BACKUP"; die "Could not write $AUTHELIA_CONFIG"; }
        n=$((n + 1))
    done <<<"$plan"
    finish_change "Removed $DOMAIN_ARG from $n rule change(s)"
    maybe_restart
}

# --------------------------------------------------------------------------
# Groups
# --------------------------------------------------------------------------

groups_of() {
    authelia_user_groups "$1" | paste -sd, -
}

cmd_set_groups() {
    require_root
    ((${#ARGS[@]} == 2)) || die "Usage: set-groups <user> g1,g2 [--exact]"
    local user="${ARGS[0]}" g
    check_username "$user"
    require_file_backend
    local -a wanted=()
    while IFS= read -r g; do
        validate_group "$g" || die "Invalid group name: $g"
        is_known_group "$g" || die "Unknown group: $g (allowed: $KNOWN_GROUPS)"
        wanted+=("$g")
    done < <(split_csv "${ARGS[1]}")
    authelia_user_exists "$user" || die "Authelia user $user not found"

    if ((!EXACT)); then
        # Keep the base groups the user already has.
        local cur d
        while IFS= read -r cur; do
            while IFS= read -r d; do
                [[ "$cur" == "$d" ]] && wanted+=("$cur")
            done < <(split_csv "$DEFAULT_USER_GROUPS")
        done < <(authelia_user_groups "$user")
    fi
    ((${#wanted[@]})) || die "Refusing to leave $user without any group (use revoke-user.sh to remove access)"
    local csv before
    csv="$(IFS=,; printf '%s' "${wanted[*]}")"
    before="$(groups_of "$user")"

    begin_change
    authelia_set_groups "$user" "$csv" || { restore_from "$BACKUP"; die "Could not update groups of $user"; }
    finish_change "Groups of $user: [$before] -> [$(groups_of "$user")]"
    groups_of "$user"
}

cmd_add_group() {
    require_root
    ((${#ARGS[@]} == 2)) || die "Usage: add-group <user> <group>"
    local user="${ARGS[0]}" group="${ARGS[1]}"
    check_username "$user"
    validate_group "$group" || die "Invalid group name: $group"
    is_known_group "$group" || die "Unknown group: $group (allowed: $KNOWN_GROUPS)"
    require_file_backend
    authelia_user_exists "$user" || die "Authelia user $user not found"
    begin_change
    authelia_add_group "$user" "$group" || { restore_from "$BACKUP"; die "Could not update groups of $user"; }
    finish_change "Added $user to $group"
    groups_of "$user"
}

cmd_remove_group() {
    require_root
    ((${#ARGS[@]} == 2)) || die "Usage: remove-group <user> <group>"
    local user="${ARGS[0]}" group="${ARGS[1]}"
    check_username "$user"
    validate_group "$group" || die "Invalid group name: $group"
    require_file_backend
    authelia_user_exists "$user" || die "Authelia user $user not found"
    local current
    current="$(authelia_user_groups "$user")"
    grep -qxF -- "$group" <<<"$current" || die "$user is not in group $group"
    begin_change
    authelia_remove_group "$user" "$group" || { restore_from "$BACKUP"; die "Could not update groups of $user"; }
    finish_change "Removed $user from $group"
    groups_of "$user"
}

# --------------------------------------------------------------------------
# Maintenance
# --------------------------------------------------------------------------

cmd_validate() {
    validate_all || die "Validation failed"
    success "Configuration is valid"
}

cmd_backup() {
    require_root
    ztvpn_lock policy
    make_backup
}

cmd_restore() {
    require_root
    ((${#ARGS[@]} == 1)) || die "Usage: restore <backup-name|path>"
    local src="${ARGS[0]}" base
    [[ "$src" == */* ]] || src="$POLICY_BACKUP_DIR/$src"
    src="$(readlink -f "$src")" || die "Backup not found"
    base="$(readlink -f "$POLICY_BACKUP_DIR")"
    [[ "$src" == "$base"/* && -d "$src" ]] || die "Backup must be a directory under $POLICY_BACKUP_DIR"
    [[ -f "$src/$(basename "$AUTHELIA_CONFIG")" || -f "$src/$(basename "$AUTHELIA_USERS_DB")" ]] ||
        die "$src contains neither $(basename "$AUTHELIA_CONFIG") nor $(basename "$AUTHELIA_USERS_DB")"

    begin_change
    restore_from "$src" || { restore_from "$BACKUP"; die "Could not restore $src"; }
    finish_change "Restored $src"
    maybe_restart
}

case "$COMMAND" in
    list-rules)   cmd_list_rules ;;
    add-rule)     cmd_add_rule ;;
    remove-rule)  cmd_remove_rule ;;
    set-groups)   cmd_set_groups ;;
    add-group)    cmd_add_group ;;
    remove-group) cmd_remove_group ;;
    validate)     cmd_validate ;;
    backup)       cmd_backup ;;
    restore)      cmd_restore ;;
esac
