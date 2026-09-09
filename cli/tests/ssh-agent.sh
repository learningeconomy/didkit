#!/bin/sh
# Example/test of using DIDKit with ssh-agent for signing
set -eu
cargo build -p didkit-cli
script_dir=$(cd "$(dirname "$0")" && pwd)
export PATH="$script_dir/../../target/debug:$PATH"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

eval "$(ssh-agent -s)"
trap 'ssh-agent -k >/dev/null; rm -rf "$work_dir"' EXIT
cd "$work_dir"
for alg in ed25519 ecdsa; do
	ssh-keygen -q -N '' -t $alg -f id_$alg
	cut -f1 -d' ' id_$alg.pub
	didkit ssh-pk-to-jwk "$(cat id_$alg.pub)" > pk_$alg
	ssh-add -q id_$alg
	did=$(didkit key-to-did key -k pk_$alg)
	vm=$(didkit key-to-verification-method key -k pk_$alg)
	didkit did-auth -H "$did" -v "$vm" -k pk_$alg --ssh-agent > didauth.jsonld
	didkit vc-verify-presentation < didauth.jsonld; echo
	rm id_$alg id_$alg.pub pk_$alg
done
# rsa is not tested because there is no generative DID method for it
