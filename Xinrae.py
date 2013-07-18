#!/usr/bin/python2.7

#==  Xinrae  script:  ==
# Author: Trigul
# Version: 1.0.6
# Licanse: GNU/GPLv3
#
# TODO: 
# backup rotation 


#== Import modules =====

import  os
import  time
import  sys
import  logging
import  random
import  string
import  re
import  glob
import  smtplib

from    optparse            import  OptionParser
from    email.MIMEMultipart import MIMEMultipart
from    email.MIMEBase      import MIMEBase
from    email.MIMEText      import MIMEText
from    email               import Encoders

#== Xinrae's Options ================
xinrae_path            = '/var/Xinrae/'

# Mysql options:
dump_options            = '--opt -e'
dump_user               = '$MYSQL_USER'
dump_password           = '$MYSQL_PASS'
dump_host               = 'localhost'
database_enable         = False

# Crypting:
crypt_enable            = False
key_size                = 245
public_key_file         = xinrae_path+'public_tgl-key.pem'

# rSync:
rsync_enable            = False
rsync_server            = '$SERVER_IP'
rsync_server            = 'rsync://%s/Xinrae-Sync/%s/' % (rsync_server, os.uname()[1])
rsync_options           = '-av -P --chmod=u-w,g-rwx,o-rwx'

# Backup:
backup_type             = 'None'
backup_target           = 'None'
backup_clean            = False

# Reporting:
mail_rcpt               = 'tarigul.lx@gmail.com'
gmail_user              = "$GMAIL_USER"
gmail_pwd               = "$GMAIL_PASS"


#== Define Options ==================
#xinrae_path            = os.getcwd()+'/'
meta_path               = xinrae_path+'Meta/'
logs_path               = xinrae_path+'Logs/'
back_path               = xinrae_path+'Backups/'
default_exclude         = meta_path+'exclude-defaults.list'
used_exclude            = meta_path+'exclude-backup.list'
backup_temp             = xinrae_path+'Temp/'

parser = OptionParser()

# Define user options:
parser.add_option("-p", "--path",
    default     =   "path-error",
    action      =   "store",
    type        =   "string",
    dest        =   "backup_target",
    help        =   "Define backup target path")

parser.add_option("-t", "--type",
    default     =   "type-error",
    action      =   "store",
    type        =   "string",
    dest        =   "backup_type",
    help        =   "Define backup type or name")

parser.add_option("--rsync",
    default     =   "True",
    action      =   "store_true",
    dest        =   "rsync_enable",
    help        =   "Enable rsync transsmission")

parser.add_option("--db",
    default     =   "True",
    action      =   "store_true",
    dest        =   "database_enable",
    help        =   "Create Mysql backup")


parser.add_option("--crypt",
    default     =   "True",
    action      =   "store_true",
    dest        =   "crypt_enable",
    help        =   "Enable crypt options")

parser.add_option("--clean",
    default     =   "True",
    action      =   "store_true",
    dest        =   "backup_clean",
    help        =   "Clean local files after backup (works only if rsync has been enabled)")

# Error parser:
(options, args) = parser.parse_args()

error_path = 'path-error'
error_type = 'type-error'

if str(options.backup_target) == str(error_path) and options.database_enable == False:
    print '\n Path is not determinate!\n'
    sys.exit(0)

elif str(options.backup_type) == str(error_type):
    print '\n Type is not determinate!\n'
    sys.exit(0)

elif options.database_enable == False:
    print '\n Path is not determinate!\n'

else:
    backup_target   = options.backup_target
    backup_type     = options.backup_type
    rsync_enable    = options.rsync_enable
    crypt_enable    = options.crypt_enable
    backup_clean    = options.backup_clean
    database_enable = options.database_enable

if os.path.exists(str(options.backup_target)) == False:
    if options.database_enable == False:
        print 'This path is not exist! Exit!'
        sys.exit(0)

def files_name(tyname):
    global tarball_name
    global key_name
    global clear_name

    time_name = time.strftime('%Y.%m.%d', time.localtime())
    host_name = os.uname()[1]

    tarball_name = archname = "%s_%s_%s.tgz" % (time_name, host_name, tyname)
    key_name = archname = "%s_%s_%s.key" % (time_name, host_name, tyname)
    clear_name = archname = "%s_%s_%s" % (time_name, host_name, tyname)

files_name(backup_type)
backup_name = back_path+tarball_name
log_file = logs_path+clear_name+'.log'
key_path = back_path+key_name
clear_bp_name = clear_name

#== Xinrae logging ==================
logging.basicConfig(
     filename=log_file,
     format='%(asctime)s %(levelname)s %(message)s',
     level=logging.DEBUG
     )

# Clean log file:
make_log = open(log_file, 'w')
make_log.write(' ')
make_log.close()

logging.info('Xinrae has been started!\n')

# Define Meta files
meta_file_md5 = logs_path+clear_bp_name+'.md5'
meta_file_log = logs_path+clear_bp_name+'.log'

# Create random symmetric key
def symm_key(size):
    length = size
    chars = string.ascii_letters + string.digits + '!@#$%^&*()'
    random.seed = (os.urandom(1024))
    symmetric_key = ''.join(random.choice(chars) for i in range(length))

    # write kye to file
    key_file = open(key_path,'w+')
    key_file.write(symmetric_key)
    key_file.close
    os.chmod(key_path, 0700)

    logging.info('Create symmetric key: %s' % (key_path))

# Database backup:
if database_enable == True:
    def database_backup(options, user, password, host):

        # define Backup file:
        backup_db_dir = backup_temp

        # Get database list:
        db_list="mysql -u %s -p%s -h %s --silent -N -e 'show databases'" % (user, password, host)

        # Exclude system databases:
        for database in os.popen(db_list).readlines():
            database = database.strip()

            if database == 'information_schema':
                continue
            if database == 'performance_schema':
                continue
            # Make mysql-dump to directory:
            mysqldump = "mysqldump      -u  %s  \
                                        -p%s    \
                                        -h  %s  \
                                            %s  \
                                        -c  %s > %s/%s.sql" % (
                                                user,
                                                password,
                                                host,
                                                options,
                                                database,
                                                backup_db_dir,
                                                database
                                                )

            os.system(mysqldump)
            logging.info("Mysql dump database: %s" %(database))

        # Create md5 hash of dumps:
        sql_hash = "md5sum %s/*.sql >> %s/DataBases.md5" % (backup_db_dir, backup_db_dir)
        os.system(sql_hash)


    database_backup(dump_options, dump_user, dump_password, dump_host)

    backup_target = backup_temp

# Create archive over tar and gzip
def backup_tgz (name, targetpath):
    tarball = name
    target = targetpath
    temp_exclude = meta_path+'exclude-temp.list'
    bp_out = name + targetpath

    # Find exclude
    search = backup_target

    exclude_file = open(default_exclude, 'r')
    lines =  exclude_file.readlines()

    exclude_list = []

    for line in lines:
        if search in line:
            exclude_list.append(line)

    if len(exclude_list) != 0:
        global find_exclude
        global self_exclude

        excl_len = exclude_list
        exclude_list = str(exclude_list)
        self_exclude = exclude_list

        exclude_list = exclude_list.replace("['", "-path ")
        exclude_list = exclude_list.replace("'", "")
        exclude_list = exclude_list.replace("\\n, ", " -o -path ")
        exclude_list = exclude_list.replace("\\n]", "")

        if len(excl_len) == 1:
            exclude_list = '\( ' + exclude_list + ' \) '

        else:
            exclude_list = '\( ' + exclude_list + ' \) -prune -o'

        if len(excl_len) == 1:

            self_exclude = self_exclude.replace("['", "")
            self_exclude = self_exclude.replace("/*\\n']", "")

            if self_exclude == targetpath:
                exclude_list = '-print'

        find_exclude = exclude_list

    else:
        find_exclude = '-print'
    find_excl = find_exclude

    # Exclude sockets:
    backup_prepare = "find %s -type s %s > %s && cat %s >> %s" % ( \
            target,
            find_excl,
            temp_exclude,
            temp_exclude,
            log_file
            )
    exclude_file.close()

    # Exclude user path in exclude-defaults:

    back_self_exclude = open(default_exclude, 'r')
    lines =  back_self_exclude.readlines()

    back_exclude = []
    for line in lines:
        back_exclude.append(line)

    back_self_exclude.close()

    back_list = back_exclude

    if len(back_exclude) != 0:

        back_self_exclude = open(default_exclude, 'r')
        lines =  back_self_exclude.readlines()

        # Self-exclude target
        search = target

        if search == '/':
            search = ' '

        if database_enable == True:
            search = 'Xinrae'


        # Search in exclude-lists
        back_exclude = []
        for line in lines:
            if search in line:
                back_exclude.append(line)

        excl_list = list(set(lines).difference(back_exclude))
        back_self_exclude.close()

        # Write new list to exclude file
        new_exclude = open(used_exclude, 'w')
        for item in excl_list:
            new_exclude.write(item)
        new_exclude.close()

        backup_exclude_path = new_exclude


    backup_exclude_path = meta_path+'exclude-backup.list'

    backup_make = "tar --create     \
        --verbose                   \
        --ignore-failed-read        \
        --preserve-permissions      \
        --recursion                 \
        --preserve-order            \
        --sparse                    \
        --totals                    \
        --use-compress-program=pigz \
        --exclude-from=%s           \
        --exclude-from=%s           \
        --file %s %s                \
        2>  /var/Xinrae/backup.log 1> /dev/null " % (
                                backup_exclude_path,
                                temp_exclude,
                                tarball,
                                target,
                                )

    file_md5 = "md5sum %s > %s" % (tarball, meta_file_md5)

    back_log = "cat backup.log >> %s && rm -f backup.log" % (log_file)

    logging.info('Search and exclude sockets:\n')
    os.system(backup_prepare)

    logging.info('Backup process started:\n')
    os.system(backup_make)
    os.system(back_log)

    os.system(file_md5)

    os.remove(temp_exclude)
    os.remove(backup_exclude_path)

backup_tgz(backup_name, backup_target)


# Crypt Backup file
if crypt_enable == True:
    def crypt(tarball, skey, pkey):
        if os.path.isfile(tarball) and os.path.isfile(skey) and os.path.isfile(pkey):
            # Symetric crypt on tarball
            symmetric_crypt = "openssl enc  \
                -aes-256-cbc                \
                -pass file:%s               \
                < %s >                      \
                %s.aes && rm -f %s"     % (
                                        skey,
                                        tarball,
                                        tarball,
                                        tarball
                                        )
            os.system(symmetric_crypt)

            skey_md5 = "md5sum %s >> %s" % (skey, meta_file_md5)
            ctarball_md5 = "md5sum %s >> %s" % (tarball+'.aes', meta_file_md5)
            logging.info('Get md5 hash of symmetric key: %s\n' % (skey))
            os.system(skey_md5)
            logging.info('Get md5 hash of crypted tarball: %s\n' % (tarball))
            os.system(ctarball_md5)

            # Asymmetric crypt on sKey
            asymmetric_crypt = "openssl rsautl  \
                -encrypt                        \
                -pubin                          \
                -inkey %s                       \
                < %s >                          \
                %s.aes && rm -f %s" % (
                                    pkey,
                                    skey,
                                    skey,
                                    skey
                                    )

            akey_md5 = "md5sum %s'.aes' >> %s" % (skey, meta_file_md5)

            os.system(asymmetric_crypt)
            logging.info('Crypt symmetric key as: %s.aes\n' % (skey))
            os.system(akey_md5)
            logging.info('Get md5 hash of asymmetric key: %s.aes\n' % (skey))

        else:
            logging.warn('Crypt keys - not found! Exit!\n')
            crypt_enable = False
    #        sys.exit(0)

    symm_key(key_size)
    crypt(backup_name, key_path, public_key_file)
else:
    logging.info('Crypting has been disabled!\n')


# Rsync to backup-server
if rsync_enable == True:
    def backup_rsync(sync_server, sync_opts, tarball):
        remoute_sync = "rsync   %s  \
                                %s  \
                                %s>>\
                                %s  " % (
                                    sync_opts,
                                    tarball,
                                    sync_server,
                                    log_file)

        # aggresive rsync:
        aggresive = True
        while aggresive:
            sync = os.system(remoute_sync)

            if sync !=0:
                global rsync_complited
                rsync_complited = False

                time.sleep(30)
                logging.warn('Cant send files!\n')

            else:
                rsync_complited = True

                aggresive = False
                logging.info('Sending files has been complited.\n')

    logging.info('Send to server tarball and key, over rsync:\n')

    if crypt_enable == True:
        backup_rsync(rsync_server, rsync_options, back_path+clear_name+'*.aes')
    else:
        backup_rsync(rsync_server, rsync_options, backup_name)

else:
    logging.info('Rsync has been disabled!\n')


# Backup Cleaning
if rsync_enable == True and backup_clean == True and rsync_complited == True:
    logging.info('Clean mode has been activated! Local backup removed!\n\n')

    # tarball 
    if os.path.exists(backup_name) == True:
        os.remove(backup_name)

    # crypted tarball
    if os.path.exists(backup_name+'.aes') == True:
        os.remove(backup_name+'.aes')

    # symmetric key
    if os.path.exists(key_path+'.aes') == True:
        os.remove(key_path+'.aes')

# Database backup cleaning:
if database_enable == True:
    db_dump = glob.glob(backup_temp+'*')
    for dumps in db_dump:
        os.remove(dumps)

logging.info('Backup has been Complited. Exit!\n\n')

# Send email-report with hash
report_body = open(log_file, 'r')
bodytext = report_body.read()

report_from     = os.uname()[1]+' <soothing.tgl@gmail.com>'
report_to       = mail_rcpt
report_subj     = 'Xinrae: [ ' + clear_bp_name + ' ] Backup Report'
report_text     = bodytext
report_attach   = meta_file_md5

report_body.close()

def send_report(send_to, subject, text, attach):
   msg = MIMEMultipart()

   msg['From'] = gmail_user
   msg['To'] = send_to
   msg['Subject'] = subject


   msg.attach(MIMEText(text))

   #== File's Attaching: ===
   if os.path.isfile(attach):
      part = MIMEBase('application', 'octet-stream')
      part.set_payload(open(attach, 'rb').read())
      Encoders.encode_base64(part)
      part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(attach))
      msg.attach(part)

   #== Relay connection ====
   mailServer = smtplib.SMTP("smtp.gmail.com", 587)
   mailServer.ehlo()
   mailServer.starttls()
   mailServer.ehlo()
   mailServer.login(gmail_user, gmail_pwd)

   #== Send email: ==========
   mailServer.sendmail(gmail_user, send_to, msg.as_string())
   mailServer.quit()

send_report(
    report_to,
    report_subj,
    report_text,
    report_attach,
    )

sys.exit(0)
