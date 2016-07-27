#!/bin/sh

wrap_in_html_if_url()
{
	case "$1" in
	*://*)
		FILE_ARGUMENT=$(mktemp)

		echo -n '<html><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>' > $FILE_ARGUMENT
		echo -n '<meta HTTP-EQUIV="REFRESH" content="0; url=' >> $FILE_ARGUMENT
		echo -n "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g' >> $FILE_ARGUMENT
		echo '"/></html>' >> $FILE_ARGUMENT
		;;
	*)
		FILE_ARGUMENT="$1"
		;;
	esac
}

