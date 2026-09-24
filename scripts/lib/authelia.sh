# shellcheck shell=bash
# Authelia file-backend user database helpers. Sourced by common.sh.
#
# All values are handed to yq through the environment (strenv) and never
# spliced into the expression, so user-controlled strings cannot rewrite
# the database. Requires mikefarah yq v4.

require_yq() {
    command -v yq >/dev/null 2>&1 || { error "yq (mikefarah v4) is required"; return 1; }
    yq --version 2>&1 | grep -q 'mikefarah' || { error "Found a yq that is not mikefarah/yq v4"; return 1; }
}

authelia_init_users_db() {
    [[ -f "$AUTHELIA_USERS_DB" ]] && return 0
    mkdir -p "$(dirname "$AUTHELIA_USERS_DB")"
    printf 'users: {}\n' | atomic_write "$AUTHELIA_USERS_DB" 600
}

authelia_user_exists() {
    [[ -f "$AUTHELIA_USERS_DB" ]] || return 1
    [[ "$(U="$1" yq '.users | has(strenv(U))' "$AUTHELIA_USERS_DB")" == "true" ]]
}

authelia_user_field() {
    U="$1" F="$2" yq '.users[strenv(U)][strenv(F)] | select(. != null)' "$AUTHELIA_USERS_DB"
}

authelia_user_groups() {
    U="$1" yq '.users[strenv(U)].groups[]?' "$AUTHELIA_USERS_DB"
}

# Reads the password from stdin, prints an argon2id PHC string with
# Authelia's default parameters (m=64MiB, t=3, p=4). The password never
# appears on a command line.
authelia_hash_password() {
    command -v argon2 >/dev/null 2>&1 || { error "argon2 CLI is required (apt install argon2)"; return 1; }
    local salt
    salt="$(openssl rand -base64 16 | tr -d '\n=')"
    # argon2 hashes stdin byte-exact; strip the single trailing newline
    # that a here-string or echo would add.
    local pw
    IFS= read -r pw || [[ -n "$pw" ]] || return 1
    printf '%s' "$pw" | argon2 "$salt" -id -t 3 -k 65536 -p 4 -l 32 -e
}

# authelia_add_user <user> <displayname> <email> <password-hash> <groups-csv>
authelia_add_user() {
    local user="$1" display="$2" email="$3" hash="$4" groups_csv="$5" g
    validate_username "$user" || { error "Invalid username: $user"; return 1; }
    validate_display_name "$display" || { error "Invalid display name"; return 1; }
    validate_email "$email" || { error "Invalid email: $email"; return 1; }
    [[ "$hash" == "\$argon2id\$"* ]] || { error "Password hash is not argon2id"; return 1; }
    local -a groups=()
    while IFS= read -r g; do
        validate_group "$g" || { error "Invalid group: $g"; return 1; }
        groups+=("$g")
    done < <(split_csv "$groups_csv")

    authelia_init_users_db
    authelia_user_exists "$user" && { error "Authelia user $user already exists"; return 1; }

    local groups_json
    groups_json="$(printf '%s\n' "${groups[@]}" | jq -R . | jq -sc .)"
    U="$user" D="$display" E="$email" H="$hash" G="$groups_json" \
        yq '.users[strenv(U)] = {"disabled": false, "displayname": strenv(D), "password": strenv(H), "email": strenv(E), "groups": (strenv(G) | from_json)}' \
        "$AUTHELIA_USERS_DB" | atomic_write "$AUTHELIA_USERS_DB" 600
}

authelia_set_disabled() {
    local user="$1" disabled="$2"
    [[ "$disabled" == true || "$disabled" == false ]] || return 1
    authelia_user_exists "$user" || { error "Authelia user $user not found"; return 1; }
    U="$user" V="$disabled" yq '.users[strenv(U)].disabled = (strenv(V) == "true")' \
        "$AUTHELIA_USERS_DB" | atomic_write "$AUTHELIA_USERS_DB" 600
}

authelia_set_password_hash() {
    local user="$1" hash="$2"
    [[ "$hash" == "\$argon2id\$"* ]] || return 1
    authelia_user_exists "$user" || { error "Authelia user $user not found"; return 1; }
    U="$user" H="$hash" yq '.users[strenv(U)].password = strenv(H)' \
        "$AUTHELIA_USERS_DB" | atomic_write "$AUTHELIA_USERS_DB" 600
}

# Replaces the user's groups. authelia_set_groups <user> <groups-csv>
authelia_set_groups() {
    local user="$1" g groups_json
    local -a groups=()
    while IFS= read -r g; do
        validate_group "$g" || { error "Invalid group: $g"; return 1; }
        groups+=("$g")
    done < <(split_csv "$2")
    authelia_user_exists "$user" || { error "Authelia user $user not found"; return 1; }
    groups_json="$(printf '%s\n' "${groups[@]}" | jq -R . | jq -sc 'map(select(length > 0)) | unique')"
    U="$user" G="$groups_json" yq '.users[strenv(U)].groups = (strenv(G) | from_json)' \
        "$AUTHELIA_USERS_DB" | atomic_write "$AUTHELIA_USERS_DB" 600
}

authelia_add_group() {
    local user="$1" group="$2"
    validate_group "$group" || { error "Invalid group: $group"; return 1; }
    authelia_user_exists "$user" || { error "Authelia user $user not found"; return 1; }
    U="$user" G="$group" yq '.users[strenv(U)].groups = ((.users[strenv(U)].groups // []) + [strenv(G)] | unique)' \
        "$AUTHELIA_USERS_DB" | atomic_write "$AUTHELIA_USERS_DB" 600
}

authelia_remove_group() {
    local user="$1" group="$2"
    authelia_user_exists "$user" || { error "Authelia user $user not found"; return 1; }
    U="$user" G="$group" yq '.users[strenv(U)].groups = ((.users[strenv(U)].groups // []) - [strenv(G)])' \
        "$AUTHELIA_USERS_DB" | atomic_write "$AUTHELIA_USERS_DB" 600
}

authelia_delete_user() {
    local user="$1"
    authelia_user_exists "$user" || return 1
    U="$user" yq 'del(.users[strenv(U)])' "$AUTHELIA_USERS_DB" | atomic_write "$AUTHELIA_USERS_DB" 600
}

authelia_list_users() {
    [[ -f "$AUTHELIA_USERS_DB" ]] || return 0
    yq '.users | keys | .[]' "$AUTHELIA_USERS_DB"
}
