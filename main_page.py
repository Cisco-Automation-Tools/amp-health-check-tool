"""
Main Page of AMP Health Checker.  This is to help customer's identify their own issues without \
    having to open a TAC case.
"""
import json
import logging
import os
import tempfile
import time

import PySimpleGUI as sg
import certifi_win32 as c
from schema import SchemaError

import popups
from amp_settings import SettingsManager
from data import Data

active_button_color = ('white', '#28a745')
default_button_color = ('black', '#F0F0F0')


def main():
    """
    This is the main function that ties all other components together:
    """

    # Read the cert data
    cert_data = "\n".join(
        list(c.wincerts.get_pems()) +
        list(c.wincerts.get_pems_wincertstore()
             )).encode()

    # Write the cert data to a temporary file
    handle = tempfile.NamedTemporaryFile(delete=False)
    handle.write(cert_data)
    handle.flush()

    # Set the temporary file name to an environment variable for the requests package
    os.environ['REQUESTS_CA_BUNDLE'] = handle.name

    logging.basicConfig(
        format='%(asctime)s %(name)-12s %(levelname)-8s %(filename)s %(funcName)s %(message)s',
        datefmt='%m-%d %H:%M:%S',
        level=logging.INFO,
        filename="amp_health_checker_log.log"
    )
    logging.warning("AMP Health Checker logging level is %s",
                    logging.getLevelName(logging.getLogger().level))
    logging.debug("%s: Starting Health Checker", time.ctime())

    try:
        settings_manager = SettingsManager()
        settings_manager.load_from_disk()
    except json.decoder.JSONDecodeError as e:
        errmsg = '%s: line %d column %d (char %d)' % (e.msg, e.lineno, e.colno, e.pos)
        sg.Popup(f"Configration file is not valid JSON. Cannot proceed.\n{errmsg}", title="AMP not found")
        logging.critical("Configration file is not valid JSON. Cannot proceed.")
        exit(1)
    except SchemaError as e:
        sg.Popup(f"Configuration file contains bad Schema. Cannot Proceed.\n{e.code}", title="AMP not found")
        logging.critical(f"Configuration file contains bad Schema. Cannot Proceed. {e.code}")
        exit(1)
    except Exception as e:
        sg.Popup(f"Unknown Error. Cannot Proceed.\n{str(e)}", title="AMP not found")
        logging.critical(f"Unknown Error. Cannot Proceed. {str(e)}")
        exit(1)

    x_count = 0

    button_size = (20, 1)
    layout = [
        [sg.Text("AMP Version: ", tooltip="The current AMP version running on the system."),
         sg.Text("Loading...", key='_version')
         ],
        [sg.Text("CPU Usage: ", tooltip="The current amount of CPU utilized by AMP executables."),
         sg.Text("0", key='_cpu', size=(5, 1))
         ],
        [sg.Text("AMP Uptime: ", size=(10, 1)),
         sg.Text("", size=(27, 1), key="_uptime",
                 tooltip="Time since AMP was last stopped")
         ],
        [sg.Text("Isolation: ", tooltip="Shows if the connector is Isolated or Not Isolated. "
                                        "Refresh with Refresh button."),
         sg.Text("", size=(12, 1), key="_isolated"),
         sg.Text("",
                 tooltip="If Isolated, shows the unlock code. Requires valid API Credentials .",
                 size=(17, 1),
                 key="_unlock_code")
         ],
        [sg.Text('_' * 50)],
        [sg.Text("TETRA Version: ", size=(11, 1)),
         sg.Text("",
                 size=(8, 1),
                 key="_tetra_version",
                 tooltip="Shows the local TETRA version.\n"
                         "Green if up to date.\n"
                         "Yellow if not within last 5 or connectivity error "
                         "to API.\nRed if TETRA is not enabled."),
         sg.Button('Check TETRA Version',
                   size=button_size,
                   button_color=default_button_color,
                   key='_tetra_version_button',
                   tooltip="Checks the API to see if TETRA is up to date. Requires Valid API Credentials."),
         sg.Text("", key="_latest_tetra_version",
                 size=(8, 1))
         ],
        [sg.Text("Policy Serial: ", size=(11, 1)),
         sg.Text("", size=(8, 1),
                 key="_policy_version",
                 tooltip="Shows the current policy serial number.\n"
                         "Green if this matches the cloud version.\n"
                         "Gray if there is a connectivity issue or invalid API Credentials.\n"
                         "Red if the local policy doesn't match the cloud version.  Try syncing policy."),
         sg.Button("Check Policy Version",
                   size=button_size,
                   button_color=default_button_color,
                   key='_policy_version_button',
                   tooltip="Checks the API to see if the policy is up to date."),
         sg.Text("", key="_latest_policy_version", size=(8, 1))
         ],
        [sg.Text("API Credentials: ",
                 size=(13, 1),
                 tooltip='Shows if the currently stored API '
                         'Credentials are valid. Can read from text file named "apiCreds.txt" in the local directory.\n'
                         'Must be in this format:\n'
                         'client_id="abcdabcdabcdabcdabcd"\n'
                         'api_key="abcd1234-abcd-1234-abcd-abcd1234abcd"'),
         sg.Text("",
                 size=(6, 1),
                 key="_api_cred_valid"),
         sg.Button("Add API Credentials",
                   button_color=default_button_color,
                   size=button_size,
                   key="-API-CREDS-",
                   tooltip="Allows user to manually input API Credentials.")],
        [sg.Text('_' * 50)],
        [sg.Button("Live Debugging",
                   button_color=default_button_color,
                   size=button_size,
                   tooltip="Live analysis used for determining potential exclusions."),
         sg.Button("Run Analysis",
                   button_color=default_button_color,
                   size=button_size,
                   tooltip="Runs analysis on the sfc.exe.log file to provide information on potential exclusions.")
         ],
        [sg.Button("Live Top Processes",
                   button_color=default_button_color,
                   size=button_size,
                   tooltip="Shows the top processes seen on the system in a live view."),
         sg.Button("Top IPs",
                   button_color=default_button_color,
                   size=button_size,
                   tooltip="Shows the top IP addresses seen on the system in a live view.")
         ],
        [sg.Button("Connectivity Test",
                   button_color=default_button_color,
                   size=button_size,
                   key="_connectivity_test",
                   tooltip="Test connection to the required servers for AMP operations."),
         sg.Button("Check Engines",
                   button_color=default_button_color,
                   size=button_size,
                   tooltip="Provides a quick view of which AMP engines are enabled on the system.")
         ],
        [sg.Button("View Exclusions",
                   button_color=default_button_color,
                   size=button_size,
                   tooltip="Shows the file and process exclusions from the local policy."),
         sg.Button("Manual SFC Analysis",
                   button_color=default_button_color,
                   size=button_size,
                   tooltip="Allows importing external sfc.exe.log files for analysis.")
         ],
        [sg.Button("Generate Diagnostic",
                   button_color=default_button_color,
                   size=button_size,
                   tooltip="Generate AMP diagnostic bundle with AMP Health Checker log. Both files "
                           "will be on the desktop."),
         sg.Button("Settings",
                   button_color=default_button_color,
                   size=button_size,
                   tooltip="Add settings view/file 4.1 credentials for api 4.2 api endpoint "
                           "4.3 update endpoint 4.4 endpoint list")
         ],
        [sg.Text('Log Level: ',
                 tooltip="Select higher log level if requested by the tool developers."),
         sg.Button('INFO', button_color=active_button_color, key='_INFO'),
         sg.Button('WARNING', button_color=default_button_color, key="_WARNING"),
         sg.Button('DEBUG', button_color=default_button_color, key="_DEBUG")
         ],
        [sg.Text('', size=(8, 1))],
        [sg.Text('', size=(13, 1)),
         sg.Button("Refresh",
                   size=(7, 1),
                   button_color=default_button_color,
                   tooltip="Refreshes calculated data, including Isolation Status."),
         sg.Button("Cancel",
                   button_color=default_button_color,
                   tooltip="Exits the program.")
         ]
    ]
    logging.debug('test')
    window = sg.Window("AMP Health Check", layout, size=(480, 540), margins=(60, 10))

    is_first = True
    d_instance = Data(settings_manager)
    while True:
        if is_first:
            event, values = window.Read(timeout=0)
            logging.debug('Event - %s : Values - %s', event, values)
            is_first = False
        else:
            event, values = window.Read(timeout=5000)

        if x_count < 10:
            x_count += 1
        else:
            if d_instance.api_cred_valid:
                d_instance.update_api_calls(settings_manager)
            x_count = 0
        d_instance.update(settings_manager)
        logging.debug('Self Scan Count = %s', d_instance.internal_health_check)
        window.FindElement('_version').Update(d_instance.version)
        window.FindElement('_cpu').Update(d_instance.current_cpu)
        window.FindElement('_uptime').Update(d_instance.converted_uptime)
        window.FindElement('_tetra_version').Update(d_instance.tetra_version_display)
        window.FindElement('_policy_version').Update(d_instance.policy_dict['policy_sn'])
        window.FindElement('_api_cred_valid').Update('Valid' if d_instance.api_cred_valid \
                                                         else 'Invalid')
        window.FindElement('_isolated').Update(d_instance.isolated)
        window.FindElement('_unlock_code').Update(d_instance.unlock_code)
        if event in (None, "Cancel"):
            break
        elif event == "_INFO":
            logging.getLogger().setLevel(logging.INFO)
            logging.info('Log level changed to %s', logging.getLevelName(
                logging.getLogger().level))
            window.FindElement('_INFO').Update(button_color=active_button_color)
            window.FindElement('_WARNING').Update(button_color=default_button_color)
            window.FindElement('_DEBUG').Update(button_color=default_button_color)
            window.Refresh()
        elif event == '_WARNING':
            logging.getLogger().setLevel(logging.WARNING)
            logging.warning('Log level changed to %s', logging.getLevelName(
                logging.getLogger().level))
            window.FindElement('_INFO').Update(button_color=default_button_color)
            window.FindElement('_WARNING').Update(button_color=active_button_color)
            window.FindElement('_DEBUG').Update(button_color=default_button_color)
            d_instance.verify_api_creds(settings_manager)
            window.Refresh()
        elif event == '_DEBUG':
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug('Log level changed to %s', logging.getLevelName(
                logging.getLogger().level))
            window.FindElement('_INFO').Update(button_color=default_button_color)
            window.FindElement('_WARNING').Update(button_color=default_button_color)
            window.FindElement('_DEBUG').Update(button_color=active_button_color)
            d_instance.verify_api_creds(settings_manager)
            window.Refresh()
        elif event == "Live Debugging":
            popups.lpap(d_instance, settings_manager)
        elif event == "Live Top Processes":
            popups.just_process(d_instance, settings_manager)
        elif event == "_tetra_version_button":
            popups.check_latest_tetra(d_instance, window, settings_manager)
        elif event == "_policy_version_button":
            popups.check_latest_policy(d_instance, window, settings_manager)
        elif event == "_connectivity_test":
            popups.connectivity(d_instance, settings_manager)
        elif event == "Check Engines":
            popups.engines_enabled(d_instance)
        elif event == "View Exclusions":
            popups.view_exclusions(d_instance)
        elif event == "Run Analysis":
            popups.analysis(d_instance, settings_manager)
        elif event == "Top IPs":
            popups.topips(d_instance, settings_manager)
        elif event == "Refresh":
            d_instance.reset_data(settings_manager)
            window.Refresh()
        elif event == "-API-CREDS-":
            popups.get_api_credentials(d_instance, settings_manager)
        elif event == "Manual SFC Analysis":
            popups.manual_sfc(d_instance, settings_manager)
        elif event == "Generate Diagnostic":
            d_instance.generate_diagnostic()
            if any(d_instance.diag_failed):
                popups.diag_failed_popup(d_instance.diag_failed)
        elif event == "Settings":
            popups.settings(settings_manager)
    if d_instance.enabled_debug:
        d_instance.disable_debug()
    # update
    window.close()


if __name__ == "__main__":
    main()
