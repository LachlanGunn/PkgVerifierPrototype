module PkgVerifierPrototype

export create_signature_repository

import TweetNaCl
import JSON

function create_signature_repository(path::AbstractString)
    if ispath(path)
        if !isdir(path)
            error("File exists at specified location.")
        elseif !isempty(readdir(path))
            error("Directory is not empty.")
        end
    else
        mkdir(path)
    end

    mkdir(joinpath(path, "masterkeys"))
    mkdir(joinpath(path, "userkeys"))
    mkdir(joinpath(path, "repo"))
    mkdir(joinpath(path, "repo", "certificates"))

    master_pk, master_sk = TweetNaCl.crypto_sign_keypair()

    secret_key_json = JSON.json(
             Dict([(:public, base64encode(master_pk)),
                   (:secret, base64encode(master_sk))]))

    fh = open(joinpath(path, "masterkeys", "secret.key"), "w")
    print(fh, secret_key_json)
    close(fh)
end

function is_valid_repository(path::AbstractString)
    if !isdir(path)
        return false
    end

    if !isdir(joinpath(path, "masterkeys"))
        return false
    end

    if !isfile(joinpath(path, "masterkeys", "secret.key"))
        return false
    end

    if !isdir(joinpath(path, "repo"))
        return false
    end

    if !isdir(joinpath(path, "repo", "certificates"))
        return false
    end

    return true

end

function create_user(path::AbstractString, user::AbstractString)
    if !is_valid_repository(path)
        error("Path is not a valid signature repository.")
    end
    
    user_pk, user_sk = TweetNaCl.crypto_sign_keypair()

    secret_key_json = JSON.json(
             Dict([(:public, base64encode(user_pk)),
                   (:secret, base64encode(user_sk))]))

    fh = open(joinpath(path, "userkeys", "$user.key"), "w")
    print(fh, secret_key_json)
    close(fh)
end

function create_user_certificate(path::AbstractString,
                                 user::AbstractString,
                                 directories)

    user_keys = get_user_keys(path, user)
    master_keys = get_master_keys(path)

    certificate = Dict([(:user, base64encode(user_keys[1])),
                        (:name, user),
                        (:directories, directories)])
    certificate_json = JSON.json(certificate)
    certificate_signed = base64encode(TweetNaCl.crypto_sign(
                                           certificate_json, master_keys[2]))

    certificate_wrapper = JSON.json(
           Dict([(:authority, base64encode(master_keys[1])),
                 (:certificate, certificate_signed)]))

    fh = open(joinpath(path, "repo", "certificates", "$user.cert"), "w")
    print(fh, certificate_wrapper)
    close(fh)
end

function get_master_keys(path::AbstractString)
    fh = open(joinpath(path, "masterkeys", "secret.key"))
    master_keys_json = readall(fh)
    close(fh)

    json_parsed = JSON.parse(master_keys_json)
    return base64decode(json_parsed["public"]),
           base64decode(json_parsed["secret"])
end

function get_user_keys(path::AbstractString, user::AbstractString)
    filename = joinpath(path, "userkeys", "$user.key") 
    fh = open(filename)
    keys_json = readall(fh)
    close(fh)

    json_parsed = JSON.parse(keys_json)
    return base64decode(json_parsed["public"]),
           base64decode(json_parsed["secret"])
end

function get_user_permissions(path::AbstractString, user::AbstractString)
    certificate_filename = joinpath(path, "repo", "certificates", "$user.cert")
    fh = open(certificate_filename)
    certificate_wrapped_json = readall(fh)
    close(fh)

    certificate_wrapped = JSON.parse(certificate_wrapped_json)

    master_pk, _ = get_master_keys(path)

    claimed_authority = base64decode(certificate_wrapped["authority"])
    if master_pk != claimed_authority
        error("Invalid certificate authority.")
    end

    certificate_json = TweetNaCl.crypto_sign_open(
                             base64decode(certificate_wrapped["certificate"]),
                             master_pk)

    certificate = JSON.parse(ASCIIString(certificate_json))
    if certificate["name"] != user
        error("Invalid user name")
    end
    return certificate["directories"]
end

function verify_user_access(path::AbstractString,
                            user::AbstractString,
                            target::AbstractString)

    allowable_directories = get_user_permissions(path, user)
    stripped_target = strip(target)

    for dir in allowable_directories
        if dir[end] != '/'
            dir = "$dir/"
        end

        if dir[1] != '/'
            dir = "/$dir"
        end

        if stripped_target[1:length(dir)] == dir
            return true
        end
    end

    return false
end

end # module
