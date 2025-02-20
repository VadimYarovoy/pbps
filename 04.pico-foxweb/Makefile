all: PICOFoxweb

clean:
	@rm -rf *.o
	@rm -rf PICOFoxweb

PICOFoxweb: main.o httpd.o
	gcc -o PICOFoxweb $^

main.o: main.c httpd.h
	gcc -c -o main.o main.c

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c

install: PICOFoxweb
	useradd -c "PICOFoxweb user" -r -s /sbin/nologin -d /var/www/picoweb pico
	install -o root -g root -m 0755 PICOFoxweb /usr/local/sbin/
	install -o root -g root -m 0644 pico.service /etc/systemd/system/
	systemctl daemon-reload
	systemctl restart pico.service
	mkdir -p /var/www/picoweb
	cp -r webroot -t /var/www/picoweb/
	chown -R pico:pico /var/www/picoweb/webroot

uninstall:
	systemctl stop pico
	rm -rf /var/www/picoweb
	rm -f /usr/local/sbin/PICOFoxweb
	rm -f /etc/systemd/system/pico.service
	systemctl daemon-reload
	userdel -f pico