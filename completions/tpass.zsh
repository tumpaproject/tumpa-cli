#compdef tpass
# Zsh completion for tpass - password store backed by tumpa keystore
# Install: tpass --completions zsh > ~/.zfunc/_tpass

_tpass_complete_entries_helper() {
	local prefix="${PASSWORD_STORE_DIR:-$HOME/.password-store}"
	prefix="${prefix%/}/"
	local -a passwords
	local _file
	for _file in "$prefix"**/*.gpg(N); do
		_file="${_file#$prefix}"
		_file="${_file%.gpg}"
		passwords+=("$_file")
	done
	_describe -t passwords 'passwords' passwords
}

_tpass_complete_entries_with_dirs() {
	_tpass_complete_entries_helper
}

_tpass() {
	local curcontext="$curcontext" state line
	typeset -A opt_args

	_arguments -C \
		'--completions[Generate shell completions]:shell:(bash zsh fish elvish powershell)' \
		'-c[Copy to clipboard]' \
		'-q[Show as QR code]' \
		'1: :->command' \
		'*: :->args'

	case $state in
		command)
			local -a commands
			commands=(
				'init:Initialize new password storage'
				'ls:List passwords'
				'show:Show existing password'
				'find:Find password files matching pattern'
				'grep:Search inside decrypted password files'
				'insert:Insert new password'
				'edit:Edit password using text editor'
				'generate:Generate new password'
				'rm:Remove existing password'
				'mv:Rename or move password'
				'cp:Copy password'
				'git:Execute git command on password store'
				'version:Show version information'
			)
			_describe -t commands 'tpass commands' commands
			_tpass_complete_entries_helper
			;;
		args)
			case ${line[1]} in
				init)
					_arguments \
						'-p[Subfolder path]:path:' \
						'*:gpg-id:'
					;;
				ls|list)
					_tpass_complete_entries_with_dirs
					;;
				show)
					_arguments \
						'-c[Copy to clipboard]' \
						'-q[Show as QR code]' \
						'*: :_tpass_complete_entries_helper'
					;;
				edit)
					_tpass_complete_entries_helper
					;;
				insert|add)
					_arguments \
						'-m[Read multiline from stdin]' \
						'-e[Echo the password]' \
						'-f[Force overwrite]' \
						'*: :_tpass_complete_entries_helper'
					;;
				generate)
					_arguments \
						'-n[No symbols]' \
						'-c[Copy to clipboard]' \
						'-q[Show as QR code]' \
						'-i[Replace first line in-place]' \
						'-f[Force overwrite]' \
						'*: :_tpass_complete_entries_helper'
					;;
				rm|remove|delete)
					_arguments \
						'-r[Recursive]' \
						'-f[Force]' \
						'*: :_tpass_complete_entries_helper'
					;;
				mv|rename|cp|copy)
					_arguments \
						'-f[Force]' \
						'*: :_tpass_complete_entries_helper'
					;;
				git)
					local -a git_commands
					git_commands=(init push pull config log reflog rebase status diff)
					_describe -t git-commands 'git commands' git_commands
					;;
			esac
			;;
	esac
}

_tpass "$@"
