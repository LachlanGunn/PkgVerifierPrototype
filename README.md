# PkgVerifierPrototype

Prototype package signing system for Julia.  Please note that for the moment
this is UNIX-only, though it is easily portable to Windows as well.

Todo:

 - Write PRNG code and build for Windows.
 - Implement package-signing certificates.

## Setup

Install the following packages

    Pkg.clone("https://github.com/LachlanGunn/TweetNaCl")
    Pkg.clone("https://github.com/PkgVerifierPrototype")

We use the TweetNaCl library---http://tweetnacl.cr.yp.to/---for
signature operations; this is included in the package above.

## Example

To set up the test repository, perform the following commands:

    using PkgVerifierPrototype

    # Change this to wherever you would like.
    repo = "/path/to/empty/directory/"

    create_signature_repository(repo)
    create_user(repo, "user1")
    create_user(repo, "user2")

Permissions are set as a list of directories.  

    create_user_certificate(repo, "user1", ["Project1A", "Project1B"])
    create_user_certificate(repo, "user2", ["Project2"])

We can check whether a user has access to a path:

    julia> verify_user_access(repo, "user1", "/Project1A/filename")
    true

    julia> verify_user_access(repo, "user1", "/Project2/filename")
    false

# Repository documentation

This is just a test system, and all keys are available at all times.  We have
not yet implemented intermediate authorities.

## Keys

Keys are stored in a JSON as Base64-encoded text.  The file format is

     { "public": "ThePublicKeyInBase64==", "secret": "TheSecretKey" }

The "masterkeys" directory contains the root key for the repository; this
key, in the file "secret.key" signs all user certificates.

User keys are stored in the "userkeys" directory, with the filename
being given by "{name}.key".  The format is as above; the name here is used
merely for lookup purposes, however it is included in the permission
certificates and thus will be validated anyway.

## Certificates

Permissions are determined by certificates signed by the master key.  These
are stored in "repo/certificates", and their format will be described shortly.
It is the "repo" directory that is to resemble what will be accessible to the
public.

Each certificate takes the name "repo/certificates/{name}.cert", and is
once again a JSON file.  These are slightly more complicated, however.  The
format is as follows:

       { "authority": "MasterPublicKeyInBase64==",
         "certificiate": "SignedCertificateInBase64==" } .

Software verifying the certificate checks that the public key included
in the certificate is trusted, and then uses it to verify and unpack
the signed data included in the "cetificate" field.  This reveals another
set of JSON data:

    { "user": "UserPublicKeyInBase64==",
      "name": "UserName",
      "directories": ["/DirectoryWithAccess", "/Another/Directory"] }

This allows a package to verify that a user has permission to sign files
under various paths.