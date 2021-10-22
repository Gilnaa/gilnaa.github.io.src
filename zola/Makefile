all:
	zola build
	cp -r public/. ../gilnaa.github.io/
	git -C ../gilnaa.github.io/ add -u
	git -C ../gilnaa.github.io/ commit -m"Update"
	git -C ../gilnaa.github.io/ push
