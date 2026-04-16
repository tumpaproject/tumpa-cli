# Bash completion for tpass - password store backed by tumpa keystore
# Install: tpass --completions bash > ~/.local/share/bash-completion/completions/tpass

_tpass_complete_entries() {
	local prefix="${PASSWORD_STORE_DIR:-$HOME/.password-store/}"
	prefix="${prefix%/}/"
	local suffix=".gpg"
	local autoexpand=${1:-0}

	local IFS=$'\n'
	local items=($(compgen -f $prefix$cur))

	local firstitem=""
	local i=0 item

	for item in ${items[@]}; do
		[[ $item =~ /\.[^/]*$ ]] && continue

		if [[ ${#items[@]} -eq 1 && $autoexpand -eq 1 ]]; then
			while [[ -d $item ]]; do
				local subitems=($(compgen -f "$item/"))
				local filtereditems=( ) item2
				for item2 in "${subitems[@]}"; do
					[[ $item2 =~ /\.[^/]*$ ]] && continue
					filtereditems+=( "$item2" )
				done
				if [[ ${#filtereditems[@]} -eq 1 ]]; then
					item="${filtereditems[0]}"
				else
					break
				fi
			done
		fi

		[[ -d $item ]] && item="$item/"

		item="${item%$suffix}"
		COMPREPLY+=("${item#$prefix}")
		if [[ $i -eq 0 ]]; then
			firstitem=$item
		fi
		let i+=1
	done

	if [[ $i -gt 1 || ( $i -eq 1 && -d $firstitem ) ]]; then
		compopt -o nospace
	fi
}

_tpass_complete_folders() {
	local prefix="${PASSWORD_STORE_DIR:-$HOME/.password-store/}"
	prefix="${prefix%/}/"

	local IFS=$'\n'
	local items=($(compgen -d $prefix$cur))
	for item in ${items[@]}; do
		[[ $item == $prefix.* ]] && continue
		COMPREPLY+=("${item#$prefix}/")
	done
}

_tpass() {
	COMPREPLY=()
	local cur="${COMP_WORDS[COMP_CWORD]}"
	local commands="init ls show find grep insert edit generate rm mv cp git version"
	if [[ $COMP_CWORD -gt 1 ]]; then
		case "${COMP_WORDS[1]}" in
			init)
				local lastarg="${COMP_WORDS[$COMP_CWORD-1]}"
				if [[ $lastarg == "-p" || $lastarg == "--path" ]]; then
					_tpass_complete_folders
					compopt -o nospace
				else
					COMPREPLY+=($(compgen -W "-p --path" -- ${cur}))
				fi
				;;
			ls|list)
				_tpass_complete_folders
				compopt -o nospace
				;;
			show|-*)
				COMPREPLY+=($(compgen -W "-c --clip -q --qrcode" -- ${cur}))
				_tpass_complete_entries 1
				;;
			edit)
				_tpass_complete_entries
				;;
			insert|add)
				COMPREPLY+=($(compgen -W "-e --echo -m --multiline -f --force" -- ${cur}))
				_tpass_complete_entries
				;;
			generate)
				COMPREPLY+=($(compgen -W "-n --no-symbols -c --clip -q --qrcode -f --force -i --in-place" -- ${cur}))
				_tpass_complete_entries
				;;
			cp|copy|mv|rename)
				COMPREPLY+=($(compgen -W "-f --force" -- ${cur}))
				_tpass_complete_entries
				;;
			rm|remove|delete)
				COMPREPLY+=($(compgen -W "-r --recursive -f --force" -- ${cur}))
				_tpass_complete_entries
				;;
			git)
				COMPREPLY+=($(compgen -W "init push pull config log reflog rebase status diff" -- ${cur}))
				;;
		esac
	else
		COMPREPLY+=($(compgen -W "${commands}" -- ${cur}))
		_tpass_complete_entries 1
	fi
}

complete -o filenames -F _tpass tpass
