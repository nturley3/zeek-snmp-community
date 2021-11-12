# Default SNMP Communtiy String Detection

Example Zeek package script for detecting and alerting on default usage of SNMP community strings.

This is a simple example and primarly used for training purposes and learning how to use the Notice framework.

If you're sending Zeek logs to a log collection system, you can replicate this behavior with default logs and alerting. 

## Installation/Upgrade


This is easiest to install through the Bro package manager::

	zkg refresh
	zkg install nturley3/zeek-snmp-community

If you need to upgrade the package::

	zkg refresh
	zkg upgrade nturley3/zeek-snmp-community

## Generated Outputs

This script generates the following notices: 

| Notice Name | Description |
| -- | -- |
| SNMP::Default_Community_String | Indicates a default community string was detected. |

## Usage

Security analysts can use the data generated here to identify systems with weak SNMP security.

Tags: Hygiene

## About

Written by Nick Turley <nickturley@gmail.com>

