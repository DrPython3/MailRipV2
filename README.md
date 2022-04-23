# Mail.Rip V2.1337
<p>
    Your SMTP checker / SMTP cracker for mailpass combolists including features like: proxy-support (SOCKS4 / SOCKS5) 
    with automatic proxy-scraper and checker, e-mail delivery / inbox check and DNS lookup for unknown SMTP-hosts.
    Made for easy usage and always working! 
</p>

<h2>Overview</h2>

<h3>Legal Notices</h3>
<p>
    <b>You are ONLY allowed to use the following code for educational purposes!</b> Mail.Rip V2.1337 shall not be used for any kind of illegal activity nor law enforcement at any time.
    This restriction applies to all cases of usage, no matter whether the code as a whole or only parts of it are being used.
</p>
<p>
    <i>By downloading and / or using any part of the code and / or any file of this repository, you agree to this restriction without remarks.</i>
</p>

___

<h3>Features</h3>
<p>
    Mail.Rip V2.1337 is a SMTP checker / SMTP cracker written in Python 3.8. Using the "smtplib", it allows you to check common mailpass combolists for valid SMTP logins.
    It has <b>included dictionaries and lists containing details of common email providers as well as most common ports used for SMTP servers.</b>
    In case any data is missing, "dnspython" is used to <b>lookup unknown SMTP hosts in MX records</b>.
</p>
<p>
    Moreover, Mail.Rip V2.1337 comes with <b>SOCKS-proxy support</b> including a <b>proxy-scraper and checker</b> function. If the proxy-support is activated, the checker / cracker scrapes SOCKS4 or SOCKS5 proxys from common online sources and will check the results, then.. The working <b>proxys</b> will be <b>used randomly</b>. And you can add new sources by editing the <i>library.json</i> at any time.
</p>
<p>
    Last but not least, Mail.Rip V2.1337 includes an <b>email delivery test / inbox check</b> for found SMTP logins. For every valid combo, it tries to send a plain text email with the
    found SMTP login. All test messages are sent to your own user-defined receiving address whereby the content of the test emails is generated randomly. The templates can be edited in the "library.json", too.
</p>
<p>
    <b>Mail.Rip V2.1337 is full functional and ready to use!</b>
</p>

___

<h2>How-to use Mail.Rip V2.1337</h2>
<p>
    <b>Mail.Rip V2.1337</b> has been written and tested with Python 3.8. It should run on any OS as long as Python and all dependencies are installed.<br>
    Just follow the steps below!
</p>

<h3>Installing needed Python modules</h3>
<p>
    All Python modules / packages needed are listed in the txt-file <i>requirements.txt</i>. For an easy installation, type:
</p>

```
pip3 install -r requirements.txt
```

<p>
    Installing any missing dependencies may take some time. Be patient, please.
</p>

<h2>Start the Checker / Cracker</h2>
<p>
    With all dependencies being installed, you can start Mail.Rip V2.1337 with:
</p>

```
python3 MailRipV2.py
```

<p>
    No extra arguments are needed. You only need to copy your combofile into the same directory before starting the checker 
    / cracker. After starting it, just follow the steps from (1) to (4). For more information see "Options in Main Menu".<br>
    <br>
    <b>Please regard:</b><br>
    Your combofile needs to be encoded with utf-8! Any other encoding may cause errors.
</p>

<h3>Options in Main Menu</h3>

<h4>[1] Set Default Values</h4>
<p>
    Use this option to edit the default values for Mail.Rip V2.1337. You can edit the following here:
</p>
<p>
    <ul>
        <li>Wether to send a test mail to a email you own</li>
        <li>Amount of threads to use for checking / cracking.</li>
        <li>Default timeout for connections.</li>
        <li>De-/activate the blacklist check for email domains.</li>
        <li>Set your email address as receiver for test messages.</li>
    </ul>
</p>

<h4>[2] De-/Activate Proxy-Support</h4>
<p>
    This option allows you to activate or deactivate the proxy-support. If activated, you will be asked for the proxy-type to use.
    Just enter <i>SOCKS4</i> or <i>SOCKS5</i>. The scraper starts automatically then. You can add more sources by editing the <i>library.json</i>. After the scraping is done, you will be asked whether you want to skip the checker. DO NOT SKIP THE CHECKER except you really, really need to start an attack immediately.
</p>

<h4>[3] Load Combos</h4>
<p>
    Option [3] starts the <b>Comboloader</b>. Enter the name of your combofile, for example: <i>combos.txt</i>. All combos in the file will be loaded 
    and prepared for an attack. Therefor, the Comboloader performs the following steps:
</p>
<p>
    <ul>
        <li>Any other separator than ":" is replaced.</li>
        <li>The email address in the combo is verified by its format using regular expressions.</li>
        <li>For verified email addresses, the domain is checked against the blacklist included in <i>library.json</i>.</li>
        <li>Then, the loader checks whether it has already loaded the given combo before (duplicates check).</li>
    </ul>
</p>
<p>
    All combos passing the checks will be loaded for an attack and saved to a txt-file called <i>targets.txt</i>. <b>Please make sure that your combofile is encoded with utf-8</b> or errors may occur.
</p>

<h4>[4] Start Attack</h4>
<p>
    This one is obvious.
</p>

___

<h2>Various</h2>
<p>
    See the sections below for any tips, hints and other information.
</p>

<h3>SMTP cracking / SMTP checking process</h3>
<p>
    Mail.Rip V2.1337 uses the smtplib for the checking / cracking process. The "magic" is done this way:
</p>
<p>
    <ol>
        <li>The SMTP cracker / SMTP checker reads the next combo from the list loaded.</li>
        <li>It looks up the email domain in the "smtphost" dictionary for the SMTP-host to attack.</li>
        <li>For unknown hosts, it will try to get the address from the MX records of the email domain.</li>
        <li>The connection port for host found in MX records is searched using the most common ones in a trial and error process.</li>
        <li>Afterwards it establishes a connection to the SMTP host (trying SSL and non-SSL as well as TLS)</li>
        <li>and sends the login data using the target email address and the given password from the combo.</li>
        <li>If the login is denied, the cracker / checker will try to login with the user-ID (email without @...) and the password.</li>
        <li>In case the login data is valid, the so-called "hit" will be saved to a txt-file.</li>
        <li>In the end Mail.Rip V2.1337 will try to send a test message to you using the found SMTP.</li>
    </ol>
</p>
<p>
    For best results every user should edit the host information in the <i>library.json</i> before starting Mail.Rip V2.1337 the 
    first time. Adding the data of the most common e-mail providers in a combolist will always speed up the checking / cracking
    process. And it will probably raise less security flags on the server-side.
</p>
<p>
    Other ways to improve your results are: deactivating the proxy-support and adjusting default values. In fact, <b>IT IS RECOMMENDED TO LEAVE THE PROXY-SUPPORT DEACTIVATED.</b> Without using proxys, you will receive much better results - for the checker as well as for the inbox check.
</p>

<h3>Notes on the email delivery test (inbox check)</h3>
<p>
    The email content is generated randomly using templates in the "library.json". Edit those templates for your needs.
    Editing the templates from time to time will provide a higher success rate.
</p>
<p>
    Always regard that the email delivery test may return false negative results for many reasons. It just confirms that the 
    given SMTP host can be used for sending emails with any software. Well-known email providers may block or restrict 
    access to SMTP accounts, especially for tools like Mail.Rip V2.1337. Moreover, free proxys may be blacklisted as well as the certain SMTP account itself. You should test valid logins for which the delivery test failed again after the attack has been finished.
</p>

<h3>Notes on the blacklist check</h3>
<p>
    The <i>library.json</i> includes a blacklist for email domains. More than 500 trashmail domains have been added to it.
    But there are also some very popular email providers on it. Those email providers are most often a waste of time when 
    you check or crack mailpass combolists. Sometimes they just block the access, sometimes they ask for further verification.
</p>
<p>
    If you want to attack those providers, too, edit the blacklist for your needs.
</p>

___

<h2>Support Mail.Rip V2.1337</h2>
<p>
    If you like Mail.Rip V2.1337 support it, please! Every donation helps. Or just buy us coffee! The more 
    coffee we drink the more time we can spend on projects like this one. Just use the wallets (BTC / LTC / XMR) below for your donation. All donations are appreciated - no matter how much you send. A single Dollar can keep us awake for one or two hours ... ;-)
</p>

<h3>Donation wallets</h3>
<p>
    - DrPython3
    <ul>
        <li><b>BTC (Bitcoin):</b> 1CU8WukMCDmeBfqJpsR4Vq9kxvNiRdYhf5</li>
        <li><b>LTC (Litecoin):</b> LeJsHzcMixhvR1qEfgHJU32joVAJDgQwR7</li>
    </ul>
    - Nexus
    <ul>
        <li><b>XMR (Monero): </b> 4AkFxzDMmVMUFheuaohXrkGDUDPRCuKcJF7ajnXzSeipFHuPWbPiZTZTs5VDQux7fcgK5WV2vZwPY8qEqyV14nBUPwSxQkN</li>
    </ul>
</p>

___

<h4>Last Update</h4>
<p>
    Date can be different from the commit date
    <br>
    2022-03-21: release v2.1337 - Enhanced edition :P
</p>
