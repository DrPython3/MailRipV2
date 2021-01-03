# Mail.Rip v2
<p>
    Your SMTP checker / SMTP cracker for mailpass combolists including features like: proxy-support (SOCKS4 / SOCKS5) 
    with automatic proxy-scraper, e-mail delivery test for valid combos (inbox check) and DNS lookup for unknown 
    SMTP-hosts.
</p>

<h2>Overview</h2>

<h3>Legal Notices</h3>
<p>
    <b>You are allowed to use the following code for educational purposes only!</b> Mail.Rip v2 shall not be used for any kind of illegal activity nor law enforcement at any time.
    This restriction applies to all cases of usage, no matter whether the code as a whole or only parts of it are being used.
</p>

<h3>Features</h3>
<p>
    Mail.Rip v2 is a SMTP checker / SMTP cracker written in Python 3.8. Using the "smtplib", it allows you to check common mailpass combolists for valid SMTP logins.
    It has <b>included dictionaries and lists containing server details of common e-mail providers as well as most common subdomains and ports used for SMTP servers.</b>
    Besides that, "dnspython" is used to <b>lookup unknown SMTP hosts in MX records</b>. In case it fails, the cracker / checker will try to <b>find the target-server 
    by using the most common subdomains and ports</b> in a connection-test by trial and error.
</p>
<p>
    Moreover, Mail.Rip v2 comes with <b>SOCKS-proxy support</b> and a <b>proxy-scraper</b> function. If the proxy-support is activated, the checker / cracker scrapes 
    SOCKS4 or SOCKS5 proxys from common online sources. The scraped <b>proxys</b> will be <b>used randomly</b>. And you can add new sources by editing the <i>library.json</i>.
</p>
<p>
    Last but not least, Mail.Rip v2 includes an <b>e-mail delivery test</b> for found SMTP logins. For every valid combo, it tries to send a plain text e-mail with the
    found SMTP login. All test messages are sent to your user-defined receiving address. This way, the cracker / checker provides an easy verification of so called "hits"
     together with an <b>inbox test</b>.
</p>

<h2>How-to use Mail.Rip v2</h2>
<p>
    <b>Mail.Rip v2</b> has been written and tested with Python 3.8. It should run on any OS as long as Python and all dependencies are installed.<br>
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

<h3>Start the Checker / Cracker</h3>
<p>
    With all dependencies being installed, you can start Mail.Rip v2 with:
</p>

```
python3 MailRipV2.py
```

<p>
    No extra arguments are needed. You only need to copy your combofile into the same directory before starting the checker 
    / cracker. After starting it, just follow the steps from (1) to (4). For more information see "Options in Main Menu".<br>
    <br>
    <b>Please regard:</b><br>
    Your combofile needs to be encoded with utf-8!
</p>

<h3>Options in Main Menu</h3>

<h4>[1] Set Default Values</h4>
<p>
    Use this option to edit the default values for Mail.Rip v2. You can edit the following ones here:
</p>
<p>
    <ul>
        <li>Amount of threads to use for checking / cracking.</li>
        <li>Default timeout for connections.</li>
        <li>De-/activate the blacklist check for e-mail domains.</li>
        <li>Your e-mail address as receiver for the e-mail delivery test.</li>
    </ul>
</p>

<h4>[2] De-/Activate Proxy-Support</h4>
<p>
    This option allows you to activate or deactivate the proxy-support. If activated, you will be asked for the proxy type to use.
    Just enter <i>SOCKS4</i> or <i>SOCKS5</i>. The scraper starts automatically then. You can add more sources by editing the <i>library.json</i>.
</p>

<h4>[3] Load Combos</h4>
<p>
    Option #3 starts the <b>Comboloader</b>. Enter the name of your combofile, for example: <i>combos.txt</i>. All combos in the file will be loaded 
    and prepared for an attack. Therefor, the Comboloader performs the following steps:
</p>
<p>
    <ul>
        <li>Any other separator than ":" is replaced.</li>
        <li>The e-mail address in the combo is verified by its format using regular expressions.</li>
        <li>For verified e-mail addresses, the domain is checked against the blacklist included in <i>library.json</i>.</li>
        <li>The Comboloader checks whether the combo has already been loaded (no duplicates check).</li>
    </ul>
</p>
<p>
    All combos passing the checks will be loaded for an attack and saved to a txt-file called <i>combos_cleaned.txt</i>.
</p>

<h4>[4] Start Attack</h4>
<p>
    This one is obvious.
</p>

<h2>Various</h2>
<p>
    See the sections below for any tips, hints and other information.
</p>

<h3>SMTP cracking / SMTP checking process</h3>
<p>
    Mail.Rip v2 uses the smtplib for the checking / cracking process. The "magic" is done this way:
</p>
<p>
    <ol>
        <li>The SMTP cracker / SMTP checker reads the next combo from the list loaded before.</li>
        <li>It looks up the e-mail domain in the "smtphost" dictionary for the SMTP-host to attack.</li>
        <li>For unknown hosts, it will try to get from the MX records of the e-mail domain.</li>
        <li>If still no host is found, it trys to establish a connection to guessed hosts using most common subdomains one by one.</li>
        <li>Same for the connection port.</li>
        <li>Afterwards it establishes a connection to the SMTP host (trying SSL first and non-SSL on errors as well as TLS)</li>
        <li>and sends the login data using the target e-mail address and the given password the combo contained.</li>
        <li>If the login is denied, the cracker / checker will try to login with the user-ID (e-mail without @...) and the password.</li>
        <li>In case the login data is valid, the so-called "hit" will be saved to a txt-file.</li>
        <li>In the end Mail.Rip v2 will try to send a test message using the found SMTP.</li>
    </ol>
</p>
<p>
    For best results every user should edit the host information in the <i>library.json</i> before starting Mail.Rip v2 for the 
    first time. Adding the data of the most common e-mail providers in a combolist will always speed up the checking / cracking
    process. And it will raise less security flags on the server-side.
</p>
<p>
    Other ways to improve your results are: deactivating the proxy-support and adjusting default values.
</p>

<h3>Notes on the e-mail delivery test (inbox check)</h3>
<p>
    Always regard that the e-mail delivery test may return false negative results for many reasons. It just confirms that the 
    given SMTP host can be used for sending e-mails with any software. Well-known e-mail providers may block or restrict 
    access to SMTP accounts for tools like Mail.Rip v2. Moreover, free proxys may be blacklisted as well as the certain SMTP 
    account itself. You should test valid logins for which the delivery test failed at a later time again.
</p>

<h3>Notes on the blacklist check</h3>
<p>
    The <i>library.json</i> includes a blacklist for e-mail domains. More than 500 trashmail domains have been added to it.
    But there are also some very popular e-mail providers on it. Those e-mail providers are most often a waste of time when 
    you check or crack mailpass combolists. Sometimes they just block the access, sometimes they ask for further verification.
</p>
<p>
    That is not bad - it is good! It proves the importance of 2FA methods. Nevertheless, if you want to attack those providers, 
    too, just edit the blacklist for your needs.
</p>

<h2>Support Mail.Rip v2</h2>
<p>
    If you like Mail.Rp v2 support it, please! Every donation helps with improving the code. Or just buy me coffee! The more 
    coffee I drink the more time I can spend on this project. Just use the wallets (BTC / LTC) below for your donation. All 
    donations are appreciated!
</p>

<h3>Donation wallets</h3>
<p>
    <ul>
        <li><b>BTC (Bitcoin):</b> 1CU8WukMCDmeBfqJpsR4Vq9kxvNiRdYhf5</li>
        <li><b>LTC (Litecoin):</b> LeJsHzcMixhvR1qEfgHJU32joVAJDgQwR7</li>
    </ul>
</p>

<h4>Last Update</h4>
<p>
    2021-01-03: release 3 with little improvements and minor bugfixes.
</p>
