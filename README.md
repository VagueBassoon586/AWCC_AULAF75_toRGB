# AWCC Auto RGB for AULA F75

Automatically reads the RGB color associated with a running application in **Alienware Command Center (AWCC)** and applies that color to an **AULA F75** keyboard.

## Prerequisite

This script assume you have Python 3, PowerShell installed on your machine

This script worked successfully with AWCC version 6.14.54.0 (Official Build)

## Usesage

Make sure you have predefined applications profile in AWCC

For the default RGB profile (The colour that the keyboard will revert back to when no other application will no predefined profile is running):
- Open default.txt and add a colour in there, make sure it is in HEX
- For example: "#FF5A00," "#FFFFFF," etc.

## Safety

The AWCC SQLite database is opened only for reading. The scripts do not modify FXRepository.db.

They do write to the AULA F75's persistent RGB configuration, including switching the keyboard to solid-color mode.

Do not adapt the HID write commands to another keyboard unless its protocol is known to be compatible.

## Acknowledgments

HID protocol information used by this project was derived from reverse-engineering work published in [keylux](https://github.com/SibteProf/keylux), created by [Sibte Hussain](https://github.com/SibteProf).

The original project is licensed under the https://github.com/SibteProf.
