"""
This script parses NPS logs into a more readable format.

This will look for log files in the local directory, in this format:
    iaslog*.log

These are in XML format, so they are converted to dictionaries
Each request entry is correlated to the response entry
The result is written to a JSON file, based on todays date


Modules:
    xmltodict, json, os, datetime

Classes:

    None

Functions

    get_logfiles()
        Get a list of log files in the local directory
    parse_to_dict(logfile)
        Convert an IAS logfile to a list of dictionaries
    parse_access_request(log)
        Parse an Access-Request log entry
    parse_access_reject(log)
        Parse an Access-Reject log entry
    parse_access_accept(log)
        Parse an Access-Accept log entry

Exceptions:

    None

Misc Variables:

    None

Author:
    Luke Robertson - May 2023
"""

import xmltodict
import json
import os
from datetime import datetime as dt


def get_logfiles():
    """
    Get a list of log files in the local directory

    Parameters
    ----------
    None

    Raises
    ------
    None

    Returns
    -------
    files : list
        A list of IAS log files in the local directory
    """

    # Create a list of log files in the local directory
    files = []

    # Go through each file in the local directory
    # Filter out any files that don't start with 'iaslog', and end with '.log'
    for f_name in os.listdir('.'):
        if f_name.startswith('iaslog') and f_name.endswith('.log'):
            files.append(f_name)

    return files


def parse_to_dict(logfile):
    """
    Convert an IAS logfile to a list of dictionary entries
    This is easier to work with than XML

    Parameters
    ----------
    logfile
        The logfile to parse

    Raises
    ------
    None

    Returns
    -------
    parsed_log : list
        A list of dictionaries, each representing a log entry
    """

    parsed_log = []

    # Open the file, and parse it
    with open(logfile, 'r') as log_file:
        # Go through each entry, and convert to dictionary
        for log_entry in log_file:
            log = xmltodict.parse(log_entry)['Event']
            parsed_log.append(log)

    return parsed_log


def parse_access_request(log):
    """
    Parse an Access-Request log entry
    Pull out the interesting information

    Parameters
    ----------
    log
        The log entry to parse

    Raises
    ------
    None

    Returns
    -------
    entry : dict
        A dictionary containing the parsed information
    """

    entry = {
        'type': 'Access-Request',
        'radius server': log['Computer-Name']['#text'],
        'timestamp': log['Timestamp']['#text'],
        'switch': log['Client-Friendly-Name']['#text'],
    }

    # Some types won't have a session ID
    #   NOTE: This means we can't correlate this message later
    if 'Acct-Session-Id' in log:
        entry['session_id'] = log['Acct-Session-Id']['#text']
    else:
        entry['session_id'] = 'No session ID'

    # Some types won't have a NAS Port ID
    if 'NAS-Port-Id' in log:
        entry['interface'] = log['NAS-Port-Id']['#text']
    else:
        entry['interface'] = 'No interface'

    # Some types won't have a Calling Station ID
    if 'Calling-Station-Id' in log:
        entry['supplicant'] = log['Calling-Station-Id']['#text']
    else:
        entry['supplicant'] = 'No supplicant'

    # Some types won't have a Called Station ID
    if 'Called-Station-Id' in log:
        entry['authenticator'] = log['Called-Station-Id']['#text']
    else:
        entry['authenticator'] = 'No authenticator'

    # Some types won't have a SAM Account Name
    if 'SAM-Account-Name' in log:
        entry['account'] = log['SAM-Account-Name']['#text']
    else:
        entry['account'] = 'No SAM Account Name'

    # If the request is successful, there will be a policy name
    if 'NP-Policy-Name' in log:
        entry['policy'] = log['NP-Policy-Name']['#text']
    else:
        entry['policy'] = 'No matching Policy'

    return entry


def parse_access_reject(log):
    """
    Parse an Access-Reject log entry
    Pull out the interesting information
    Convert the reason code into somethignn human-readable

    Parameters
    ----------
    log
        The log entry to parse

    Raises
    ------
    None

    Returns
    -------
    entry : dict
        A dictionary containing the parsed information
    """

    entry = {
        'type': 'Access-Reject',
        'radius server': log['Computer-Name']['#text'],
        'timestamp': log['Timestamp']['#text'],
        'switch': log['Client-Friendly-Name']['#text'],
    }

    # Some types won't have a session ID
    #   NOTE: This means we can't correlate this message later
    if 'Acct-Session-Id' in log:
        entry['session_id'] = log['Acct-Session-Id']['#text']
    else:
        entry['session_id'] = 'No session ID'

    # Some types won't have a SAM Account Name
    if 'SAM-Account-Name' in log:
        entry['account'] = log['SAM-Account-Name']['#text']
    else:
        entry['account'] = 'No SAM Account Name'

    # Convert the reason code to a human-readable string
    reason = log['Reason-Code']['#text']
    match reason:
        case '0':
            entry['reason'] = 'Success'
        case '1':
            entry['reason'] = 'Internal Error'
        case '2':
            entry['reason'] = 'Access Denied'
        case '3':
            entry['reason'] = 'Malformed Request'
        case '4':
            entry['reason'] = 'Global Catalog Error'
        case '5':
            entry['reason'] = 'Domain unavailable'
        case '6':
            entry['reason'] = 'Server unavailable'
        case '7':
            entry['reason'] = 'No such domain'
        case '8':
            entry['reason'] = 'No such user'
        case '9':
            entry['reason'] = 'Discarded by 3rd party DLL'
        case '10':
            entry['reason'] = '3rd party DLL has failed'
        case '16':
            entry['reason'] = 'Authentication failed'
        case '17':
            entry['reason'] = 'Change password failure'
        case '18':
            entry['reason'] = 'Unsupported authentication type'
        case '19':
            entry['reason'] = 'No reversibly encrypted password'
        case '20':
            entry['reason'] = 'LAN Manager authentication failed'
        case '21':
            entry['reason'] = 'Extension DLL rejected the request'
        case '22':
            entry['reason'] = 'EAP cannot be processed by the server'
        case '23':
            entry['reason'] = 'Unexpected error'
        case '32':
            entry['reason'] = 'Local users only'
        case '33':
            entry['reason'] = 'Password must change'
        case '34':
            entry['reason'] = 'Account disabled'
        case '35':
            entry['reason'] = 'Account expired'
        case '36':
            entry['reason'] = 'Account locked out'
        case '37':
            entry['reason'] = 'Outside logon hours'
        case '38':
            entry['reason'] = 'Account restriction'
        case '48':
            entry['reason'] = 'No NPS policy matched'
        case '49':
            entry['reason'] = 'Connection request policy did not match'
        case '64':
            entry['reason'] = 'Dial in locked out'
        case '65':
            entry['reason'] = 'Dial in disabled'
        case '66':
            entry['reason'] = 'Invalid authentication type'
        case '67':
            entry['reason'] = 'Invalid calling station'
        case '68':
            entry['reason'] = 'Invalid dial-in hours'
        case '69':
            entry['reason'] = 'Invalid called station'
        case '70':
            entry['reason'] = 'Invalid port type'
        case '71':
            entry['reason'] = 'Invalid restriction'
        case '72':
            entry['reason'] = 'Change password option is not enabled'
        case '73':
            entry['reason'] = 'Invalid computer certificate or EKU extension'
        case '80':
            entry['reason'] = 'No record'
        case '96':
            entry['reason'] = 'Session timeout'
        case '97':
            entry['reason'] = 'unexpected request'
        case '112':
            entry['reason'] = (
                'Remote RADIUS server did not process the request')
        case '113':
            entry['reason'] = (
                'Attempted to forward to a non-existant RADIUS server'
            )
        case '115':
            entry['reason'] = (
                'Could not forward the request to a remote server'
            )
        case '116':
            entry['reason'] = (
                'Could not forward the request to a remote server'
            )
        case '117':
            entry['reason'] = 'Remote RADIUS server did not respond'
        case '118':
            entry['reason'] = (
                'Remote RADIUS server responded with invalid packet'
            )
        case '256':
            entry['reason'] = 'Client provided a revoked certificate'
        case '257':
            entry['reason'] = 'Cannot access CRL'
        case '258':
            entry['reason'] = 'Unable to check for certificate revokation'
        case '259':
            entry['reason'] = 'The CA that manages the CRL is unavailable'
        case '260':
            entry['reason'] = 'The message has been altered'
        case '261':
            entry['reason'] = 'Cannot contact Active Directory'
        case '262':
            entry['reason'] = 'Incomplete message'
        case '263':
            entry['reason'] = 'NPS server did not receive complete credentials'
        case '264':
            entry['reason'] = 'system clocks are not synchronized'
        case '265':
            entry['reason'] = 'The client certificate is not trusted'
        case '266':
            entry['reason'] = 'The message was unexpected or malformed'
        case '267':
            entry['reason'] = 'Client certificate has inappropriate EKU'
        case '268':
            entry['reason'] = (
                'Client certificate has expired or is not yet valid'
            )
        case '269':
            entry['reason'] = 'No common security algorithms available'
        case '270':
            entry['reason'] = (
                'Smart card is required, but not used'
            )
        case '271':
            entry['reason'] = (
                'NPS server in the process of shutting down or restarting'
            )
        case '272':
            entry['reason'] = (
                'The client certificate maps to multiple accounts'
            )
        case '273':
            entry['reason'] = 'Trust provider is not recognised'
        case '274':
            entry['reason'] = 'Trust provider does not support this action'
        case '275':
            entry['reason'] = (
                'Trust provider does not support the specified data format'
            )
        case '276':
            entry['reason'] = 'EAP binary cannot be verified on the server'
        case '277':
            entry['reason'] = 'EAP binary on the server is not signed'
        case '278':
            entry['reason'] = 'Client certificate has expired'
        case '279':
            entry['reason'] = 'Client certificate validity period is not valid'
        case '280':
            entry['reason'] = 'Client certificate not issued by a valid CA'
        case '281':
            entry['reason'] = 'Client certificate chain path length exceeded'
        case '282':
            entry['reason'] = (
                '''Client certificate contains an unrecognized
                critical extension'''
            )
        case '283':
            entry['reason'] = (
                '''Client certificate does not contain
                the client authentication EKU'''
            )
        case '284':
            entry['reason'] = (
                '''Client certificate is invalid,
                as the parent cert does not match'''
            )
        case '285':
            entry['reason'] = 'NPS cannot locate the certificate'
        case '286':
            entry['reason'] = 'Certificate chain is not trusted'
        case '287':
            entry['reason'] = 'Certificate chain is not complete'
        case '288':
            entry['reason'] = 'Unspecified trust failure'
        case '289':
            entry['reason'] = 'Certificate has been revoked'
        case '290':
            entry['reason'] = (
                'Test certificate in use, but the root CA is not trusted'
            )
        case '291':
            entry['reason'] = 'NPS cannot locate the CRL'
        case '292':
            entry['reason'] = (
                '''The username attribute does not match
                the CN in the certificate'''
            )
        case '293':
            entry['reason'] = 'Certificate has the wrong EKUs'
        case '294':
            entry['reason'] = 'Certificate is explicitly marked as untrusted'
        case '295':
            entry['reason'] = 'Certificate\'s CA is not trusted'
        case '296':
            entry['reason'] = 'Certificate has the wrong EKUs'
        case '297':
            entry['reason'] = 'Certificate does not have a valid name'
        case '298':
            entry['reason'] = 'Certificate does not have a valid UPN'
        case '299':
            entry['reason'] = 'Internal verification failed'
        case '301':
            entry['reason'] = (
                'Security breach, NPS terminated the auth process'
            )
        case '302':
            entry['reason'] = 'NPS did not get a valid cryptobinding'

    return entry


def parse_access_accept(log):
    """
    Parse an Access-Accept log entry
    Pull out the interesting information

    Parameters
    ----------
    log
        The log entry to parse

    Raises
    ------
    None

    Returns
    -------
    entry : dict
        A dictionary containing the parsed information
    """

    entry = {
        'type': 'Access-Accept',
        'radius server': log['Computer-Name']['#text'],
        'timestamp': log['Timestamp']['#text'],
        'switch': log['Client-Friendly-Name']['#text'],
        'policy': log['NP-Policy-Name']['#text'],
    }

    # Some types won't have a session ID
    #   NOTE: This means we can't correlate this message later
    if 'Acct-Session-Id' in log:
        entry['session_id'] = log['Acct-Session-Id']['#text']
    else:
        entry['session_id'] = 'No session ID'

    # Some types won't have a SAM Account Name
    if 'SAM-Account-Name' in log:
        entry['account'] = log['SAM-Account-Name']['#text']
    else:
        entry['account'] = 'No SAM Account Name'

    # Get the VLAN ID, if one is assigned
    if 'Tunnel-Pvt-Group-ID' in log:
        entry['vlan'] = log['Tunnel-Pvt-Group-ID']['#text']

    # Get the EAP type, if one is used
    if 'EAP-Friendly-Name' in log:
        entry['EAP type'] = log['EAP-Friendly-Name']['#text']

    return entry


if __name__ == '__main__':
    """
    The main function

    1. Get a list of log files
    2. Work through each file, parsing it to a dictionary
    3. Parse each event, according to its type
    4. Correlate the events into a single list of dictionaries
    5. Write the list to a JSON file
    """

    # Get a list of log files
    files = get_logfiles()

    # Work through each file
    # Converts all log entries into one list of dictionaries
    cleaned_log = []
    for file in files:

        # Open the file and parse it to a dictionary
        print(f'Opening {file}')
        parsed_log = parse_to_dict(file)

        # Parse each event, according to its type
        counter = 0
        for event in parsed_log:
            log = {}

            # Get the RADIUS packet type
            event_type = event['Packet-Type']['#text']
            match event_type:
                case '1':
                    log = parse_access_request(event)
                case '2':
                    log = parse_access_accept(event)
                case '3':
                    log = parse_access_reject(event)
                case _:
                    log['type'] = f'Other {event_type}'

            cleaned_log.append(log)
            counter += 1

        print(f'\tParsed {counter} events')

    # Correlate the events
    # Looks through the full list of events and finds matching pairs
    # Use counters to provide feedback to the user
    correlated = []
    access_request_ctr = 0
    access_accept_ctr = 0
    access_reject_ctr = 0
    access_other_ctr = 0
    thousands = 0

    print("\nCorrelating events to flows")

    # Track the index here, to make correlating the next event faster
    for index, event in enumerate(cleaned_log):
        # Only look at Access-Request events to start the process
        #   We'll use other types later
        if event['type'] != 'Access-Request':
            continue

        # Get common fields from the Access-Request
        access_request_ctr += 1
        entry = {
            'session id': event['session_id'],
            'timestamp': event['timestamp'],
            'server': event['radius server'],
            'account': event['account'],
            'authenticator': event['authenticator'],
        }

        # Find the corresponding Access-Accept or Access-Reject
        # Start at the index after the last entry
        # A match should be found quickly as it's usually the next event
        for other in cleaned_log[index + 1:]:
            # Confirm that the session ID matches
            # It's possible that session IDs are reused
            #   So, we need to check the type and switch as well
            if (
                other['session_id'] == event['session_id']
                and other['type'] != event['type']
                and other['switch'] == event['switch']
            ):
                # Work out if this succeeded or failed
                if other['type'] == 'Access-Accept':
                    access_accept_ctr += 1
                    entry['result'] = 'success'
                    entry['policy'] = other['policy']

                    if 'vlan' in other:
                        entry['vlan'] = other['vlan']

                    if 'EAP type' in other:
                        entry['EAP type'] = other['EAP type']

                elif other['type'] == 'Access-Reject':
                    access_reject_ctr += 1
                    entry['result'] = 'failure'
                    entry['fail_reason'] = other['reason']

                    if 'policy' in event:
                        entry['policy'] = event['policy']

                else:
                    access_other_ctr += 1
                    entry['result'] = 'other'
                    print(f'Found an {other["type"]} event')

                break

        correlated.append(entry)

        # Provide users some feedback as we go...
        if (
            (access_accept_ctr + access_reject_ctr + access_other_ctr) -
            (thousands * 1000) > 1000
        ):
            thousands += 1
            print(f'\t{thousands}000 events correlated so far...')

    # Provide a summary of the results
    print(
        f'''\nProcessed {access_request_ctr} Access-Request events,
        {access_accept_ctr} Access-Accept events,
        {access_reject_ctr} Access-Reject events,
        and {access_other_ctr} other events'''
    )

    # Save the cleaned log to a JSON file
    today = dt.today().date()
    logfile = f'iaslog_{today}.json'
    with open(logfile, 'w') as f:
        f.write(json.dumps(correlated))
