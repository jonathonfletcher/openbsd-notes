# OpenBSD 6.9 / smtpd / dovecot


## DNS

Use DNSSEC if possible. It makes the message signing much more useful (because then the dkim record is arguably not forged / spoofed).

### A / AAAA / PTR:

A / AAAA / PTR records for mail.primary.tld have to be in place.


### MX:

    primary.tld   10  mail.primary.tld
    second.tld    10  mail.primary.tld
    third.tld     10  mail.primary.tld


### CNAME:

    imap.primary.tld -> mail.primary.tld
    smtp.primary.tld -> mail.primary.tld
    default._domainkey.primary.tld -> 20210101._domainkey.primary.tld
    default._domainkey.second.tld -> default._domainkey.primary.tld
    default._domainkey.third.tld -> default._domainkey.primary.tld

### TXT:

    20210101._domainkey.primary.tld   "v=DKIM1;k=rsa;p=1024BITPRIVATEKEYHERE_SEE_GILLES_ARTICLE;"

    primary.tld   "v=spf1 mx -all"
    second.tld  "v=spf1 mx -all"
    third.tld  "v=spf1 mx -all"

    _dmarc.primary.tld    "v=DMARC1;p=reject;pct=100;rua=mailto:postmaster@primary.tld;"
    _dmarc.second.tld     "v=DMARC1;p=reject;pct=100;rua=mailto:postmaster@second.tld;"
    _dmarc.third.tld      "v=DMARC1;p=reject;pct=100;rua=mailto:postmaster@third.tld;"


## Mail Server

### Installed Packages:

    dovecot-2.3.14p0v0
    dovecot-fts-xapian-1.4.8
    dovecot-pigeonhole-0.5.14v1
    opensmtpd-extras-6.7.1v0
    opensmtpd-filter-dkimsign-0.4
    opensmtpd-filter-rspamd-0.1.7p0
    opensmtpd-filter-senderscore-0.1.1p0


### Virtual Mail User


/etc/master.password

    vmail:*:1000:1000::0:0:Virtual Mail:/var/vmail:/sbin/nologin

/etc/group

    vmail:*:1000:

/etc/dovecot/dh.pem

```# openssl dhparam -out /etc/dovecot/dh.pem 4096```

/etc/login.conf - Put the dovecot user into a specific user class (master.passwd, and use ```cap_mkdb``` to generate the user class db from /etc/login.conf.

    dovecot:\
        :openfiles-cur=2048:\
        :openfiles-max=4096:\
        :stacksize-cur=16M:\
        :tc=daemon:


### Certificates - httpd and acme-client

/etc/acme-client.conf

    domain mail.primary.tld {
        alternative names { imap.primary.tld smtp.primary.tld }
        domain key "/etc/ssl/private/mail.primary.tld.key"
        domain full chain certificate "/etc/ssl/mail.primary.tld.fullchain.pem"
        sign with letsencrypt
    }


/etc/httpd.conf (need httpd to get the certificates ...)

    chroot "/var/www"

    server "mail.primary.tld" {
            listen on * port 80
            location "/.well-known/acme-challenge/*" {
                    root "/acme"
                    request strip 2
            }
            location * {
                    block return 302 "https://$HTTP_HOST$REQUEST_URI"
            }
    }


you will need initial ocsp info

    /usr/sbin/ocspcheck -v -N -o /etc/ssl/mail.primary.tld.ocsp /etc/ssl/mail.primary.tld.fullchain.pem


and something in cron to keep refreshing the cert and ocsp:

    @weekly	/usr/sbin/acme-client -v mail.primary.tld
    @weekly /usr/sbin/ocspcheck -v -N -o /etc/ssl/mail.primary.tld.ocsp /etc/ssl/mail.primary.tld.fullchain.pem


### smtpd

smtpd and dovecot share login info - so only one place for usernames and passwords. 

The sqlite db contains tables for virtual_users, virtual_domains, and login credentials:

/etc/mail/mail.db

    CREATE TABLE virtual_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email VARCHAR(255) NOT NULL,
        destination VARCHAR(255) NOT NULL
    );
    INSERT INTO virtual_users VALUES(1,'@primary.tld','me@primary.tld');
    INSERT INTO virtual_users VALUES(2,'me@primary.tld','vmail');
    INSERT INTO virtual_users VALUES(3,'@second.tld','me@second.tld');
    INSERT INTO virtual_users VALUES(3,'@third.tld','me@second.tld');
    INSERT INTO virtual_users VALUES(4,'me@second.tld','vmail');

the ```virtual_users``` rows that have destination ```vmail``` will be delivered (into the mailbox of the email column for that row). The '@domain' email with a known virtual user as destination makes for a catch-all. Note you can map one entire domain into a user in a different domain.

    CREATE TABLE virtual_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain VARCHAR(255) NOT NULL
    );
    INSERT INTO virtual_domains VALUES(1,'primary.tld');
    INSERT INTO virtual_domains VALUES(2,'second.tld');

The ```virtual_domains``` table is just a list of domains that you are handling

    CREATE TABLE credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL
    );
    INSERT INTO credentials VALUES(1,'me@primary.tld','$2b$10$PASSWD_ENTRY');
    INSERT INTO credentials VALUES(2,'me@second.tld','$2b$10$PASSWD_ENTRY');

```credentials``` is shared between smtpd and dovecot. use ```smtpctl encrypt``` to generate the hashed password entry (it looks the same as a 'normal' /etc/master.password entry)


/etc/mail/sqlite.conf

    dbpath /etc/mail/mail.db
    query_credentials SELECT email, password FROM credentials WHERE email=?;
    query_alias SELECT destination FROM virtual_users WHERE email=?;
    query_domain SELECT domain FROM virtual_domains WHERE domain=?;


/etc/mail/virtual_rejects - virtual addresses to reject outright

    reject@primary.tld
    reject@secondary.tld

This is a hack. Use ```makemap -t set /etc/mail/virtual_rejects``` to generate the db used by smtpd from the input text file.


/etc/mail/smtpd.conf

    pki mail.primary.tld cert "/etc/ssl/mail.primary.tld.fullchain.pem"
    pki mail.primary.tld key "/etc/ssl/private/mail.primary.tld.key"

    filter filter_check_dyndns phase connect match rdns regex { '.*\.dyn\..*', '.*\.dsl\..*' } \
        disconnect "550 no residential connections"

    filter filter_check_rdns phase connect match !rdns \
        disconnect "550 reverse dns required"

    filter filter_check_fcrdns phase connect match !fcrdns \
        disconnect "550 forward-confirmed reverse dns required"

    filter filter_senderscore \
        proc-exec "filter-senderscore -blockBelow 10 -junkBelow 70 -slowFactor 5000"

    filter filter_dkimsign \
        proc-exec "filter-dkimsign -t -d primary.tld -s default -k /etc/mail/dkim/primary.tld.key" user _dkimsign group _dkimsign


    table aliases file:/etc/mail/aliases
    table credentials sqlite:/etc/mail/sqlite.conf
    table virtual_users sqlite:/etc/mail/sqlite.conf
    table virtual_domains sqlite:/etc/mail/sqlite.conf
    table virtual_rejects db:/etc/mail/virtual_rejects.db


    listen on all tls-require tag MTA pki mail.primary.tld \
        filter { filter_check_dyndns, filter_check_rdns, filter_check_fcrdns, filter_senderscore }

    listen on all port submission tls-require tag MSA pki mail.primary.tld auth <credentials> \
        filter { filter_dkimsign }


    action act_relay relay
    action act_deliver_alias_users mbox alias <aliases>
    action act_deliver_virtual_users lmtp "/var/dovecot/lmtp" rcpt-to virtual <virtual_users>


    match for local action act_deliver_alias_users
    match from any for domain <virtual_domains> rcpt-to <virtual_rejects> reject
    match from any for domain <virtual_domains> action act_deliver_virtual_users
    match auth tag MSA from any for any action act_relay


### dovecot

/etc/dovecot/dovecot-sql.conf.ext

    driver = sqlite
    connect = /etc/mail/mail.db
    default_pass_scheme = BLF-CRYPT
    password_query = \
        SELECT email as user, password \
        FROM credentials WHERE email = '%u'

(commented-out lines omitted). This is how we tell dovecot to use the same user table as smtpd uses.


/etc/dovecot/local.conf

Messy. Sieve config omitted. 

TLS / AUTH stuff:

    ssl = required
    ssl_key = </etc/ssl/private/mail.primary.tld.key
    ssl_cert = </etc/ssl/mail.primary.tld.fullchain.pem
    ssl_dh = </etc/dovecot/dh.pem
    ssl_cipher_list = HIGH:!aNULL:!kRSA
    ssl_min_protocol = TLSv1.2
    #verbose_ssl = yes
    ssl_client_ca_dir = /etc/ssl
    ssl_client_ca_file = /etc/ssl/cert.pem
    ssl_client_require_valid_cert = no

    disable_plaintext_auth = yes

    #auth_verbose = yes
    #auth_debug = yes
    auth_username_format = %n@%d
    auth_mechanisms = plain

mail plugins, quota and zlib (compresses delivered mail on local filesystem) and xapian (full-text-search). 

    mail_plugins = $mail_plugins zlib
    mail_plugins = $mail_plugins quota
    mail_plugins = $mail_plugins fts fts_xapian

mail protocols:

    protocols = imap lmtp

virtual mail. Note that the  ```mail_uid```, ```mail_gid```, ```first_valid_uid```, ```first_valid_gid``` have to match uid / gid for the ```vmail``` user / group in /etc/master.passwd. Using Maildir as storage, with different locations for indexes and dovecot control stuff. Using LAYOUT=fs so IMAP folders are more like fileststem folders:

    mail_uid = 1000
    mail_gid = 1000
    first_valid_uid = 1000
    first_valid_gid = 1000
    default_client_limit = 512
    default_vsz_limit = 2GB

    mail_location = maildir:~/Maildir:LAYOUT=fs:INDEX=~/Maildir_index:CONTROL=~/Maildir_control
    mail_prefetch_count = 8
    mailbox_list_index = yes
    maildir_broken_filename_sizes = yes

password and user info. ```home=/var/vmail/%d/%n``` is the pattern for mailbox location on local filesystem. %d/%n expands to domain/user.

    passdb {
        driver = sql
        args = /etc/dovecot/dovecot-sql.conf.ext
    }

    userdb {
        driver = static
        args = uid=vmail gid=vmail home=/var/vmail/%d/%n
    }

    service lmtp {
        user = vmail
        unix_listener lmtp {
            #mode = 0666
        }
    }


/etc/dovecot/conf.d/20-imap.conf

      mail_plugins = $mail_plugins imap_quota

in the ```protocol imap``` section. the imap_* plugins are the imap specific parts of the protocol. 


/etc/dovecot/conf.d/90-plugin.conf

    plugin {
        zlib_save = gz
        zlib_save_level = 9
    }

    plugin {
        quota = maildir:User quota
        quota_rule = *:storage=32G
        quota_warning = storage=95%% quota-warning 95 %u
    }

    plugin {
        fts = xapian
        fts_xapian = partial=2 full=20 verbose=0
        fts_autoindex = yes
        fts_enforced = yes
    }

### misc

when using doveadm the format of the ```-u``` option is a virtual user and domain - eg me@primary.tld. 

