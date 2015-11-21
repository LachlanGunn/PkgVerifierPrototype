module PkgVerifierPrototype

export create_signature_repository, create_user, create_user_certificate, verify_user_access, get_user_certificate, construct_data_certificate, open_data_certificate, traverse_dir

import TweetNaCl
import JSON
import SHA

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

function get_user_permissions_from_certificate(path::AbstractString, certificate_wrapped::Dict)

    master_pk, _ = get_master_keys(path)

    claimed_authority = base64decode(certificate_wrapped["authority"])
    if master_pk != claimed_authority
        error("Invalid certificate authority.")
    end

    certificate_json = TweetNaCl.crypto_sign_open(
                             base64decode(certificate_wrapped["certificate"]),
                             master_pk)

    certificate = JSON.parse(ASCIIString(certificate_json))
    return base64decode(certificate["user"]), certificate["name"], certificate["directories"]
end

function get_user_permissions(path::AbstractString, user::AbstractString)
    user_pk, user_name, directories = get_user_permissions_from_certificate(
                                             path,
                                             get_user_certificate(path, user))
    if user_name != user
        error("User name does not match certificate.")
    end
    return user_pk, user_name, directories
end

function get_user_certificate(path::AbstractString, user::AbstractString)

    certificate_filename = joinpath(path, "repo", "certificates", "$user.cert")
    fh = open(certificate_filename)
    certificate_wrapped_json = readall(fh)
    close(fh)

    return JSON.parse(certificate_wrapped_json)

end

function verify_user_access(path::AbstractString,
                            user::AbstractString,
                            target::AbstractString)

    _, _, allowable_directories = get_user_permissions(path, user)
    stripped_target = strip(target)

    for dir in allowable_directories

        if dir[end] != '/'
            dir = "$dir/"
        end

        if dir[1] != '/'
            dir = "/$dir"
        end

        if length(dir) > length(stripped_target)
            continue
        end

        if stripped_target[1:length(dir)] == dir
            return true
        end
    end

    return false
end

function construct_data_certificate(repo::AbstractString,
                                    user::AbstractString,
                                    data::AbstractString)


    user_pk, user_sk = get_user_keys(repo, user)

    user_certificate = get_user_certificate(repo, user)
    
    certificate = Dict([(:signer, base64encode(user_pk)),
                        (:certificate, user_certificate),
                        (:data, base64encode(
                                    TweetNaCl.crypto_sign(data, user_sk)))])
    
    return JSON.json(certificate)
end

function open_data_certificate(repo::AbstractString,
                               certificate_json::AbstractString)

    certificate = JSON.parse(certificate_json)
    user_pk, user_name, permissions = get_user_permissions_from_certificate(
                                  repo, certificate["certificate"])

    if user_pk != base64decode(certificate["signer"])
        error("Certificate public key does not match.")
    end

    return ASCIIString(TweetNaCl.crypto_sign_open(base64decode(certificate["data"]), user_pk))
end

function hash_dir(dir::AbstractString, dir_relpath::AbstractString = "")
    const to_ignore = [".git"]

    results = []

    contents = sort(readdir(dir))
    for file in contents
        path = joinpath(dir, file)
        relpath = joinpath(dir_relpath, file)

        if isfile(path)
            # Find hash
            open(path, "r") do f
                hash = SHA.sha512(f)
                push!(results, [relpath, hash, "SHA-512"])
            end

            
        elseif isdir(path)
            if !(file in to_ignore)
                results = vcat(results, hash_dir(path, relpath))
            end
        end
    end

    return results
end

function hash_pkg(pkg::AbstractString)
    dir = Pkg.dir(pkg)
    if isdir(dir)
        return hash_dir(dir)
    else
        error("Package directory does not exist.")
    end
end

function construct_package_certificate(repo::AbstractString,
                                       user::AbstractString,
                                       pkg::AbstractString)

    hashes = hash_pkg(pkg)
    return construct_data_certificate(repo, user, JSON.json(Dict([
               ("package", pkg), ("hashes", hashes)])))
end

function verify_package_certificate(repo::AbstractString,
                                    certificate::AbstractString)

    contents = JSON.parse(open_data_certificate(repo, certificate))
    hashes_local = hash_pkg(contents["package"])
    if hashes_local != contents["hashes"]
        error("Package verification failed.")
    end
end

end # module

