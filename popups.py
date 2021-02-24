'''
This section is for all the popup GUIs off the main page.
'''
import logging
import PySimpleGUI as sg
# update
import validators
from pathlib import Path
import json
import re
import os.path
from time import sleep

# update
from data import Data, NAMADDRESSLIST
from resources import RESOURCES
from main_page import save_namurls

regex = re.compile(
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)


def analysis(data):
    '''
    Run quick analysis on the system.
    '''
    data.update()
    layout = [
        [sg.Multiline("Top 10 Processes\n" + data.get_top_processes(10), \
                      size=(200, 12), key="_top_processes")],
        [sg.Multiline("Top 10 Paths\n" + data.get_top_paths(10), \
                      size=(200, 12), key="_top_paths")],
        [sg.Multiline("Top 10 Extensions\n" + data.get_top_extensions(10), \
                      size=(200, 12), key="_top_extensions")],
        [sg.Multiline("Top 10 Folders\n" + data.get_top_folders(10), \
                      size=(200, 12), key="_top_folders")],
        [sg.Multiline("Top 10 Exclusions Hit\n" + data.get_top_exclusions(10), \
                      size=(200, 12), key="_top_exclusions")],
        [
            sg.FileSaveAs("Save As", button_color=('black', '#F0F0F0'), \
                          file_types=(("Log File", "*.log"),)),
            sg.Button("Cancel", button_color=('black', '#F0F0F0')),
        ]
    ]
    window = sg.Window("Analysis", layout, location=(1, 1))
    to_save = ""
    while True:
        event, values = window.Read(timeout=3000)
        if event in (None, "Cancel"):
            break
        data.update()
        window.Element("_top_processes").Update("Top 10 Processes\n" + data.get_top_processes(10))
        window.Element("_top_paths").Update("Top 10 Paths\n" + data.get_top_paths(10))
        window.Element("_top_extensions").Update("Top 10 Extensions\n" + data.get_top_extensions(10))
        window.Element("_top_folders").Update("Top 10 Folders\n" + data.get_top_folders(10))
        window.Element("_top_exclusions").Update("Top 10 Exclusions Hit\n" + data.get_top_exclusions(10))
        window.Refresh()
        if values.get("Save As") != to_save:
            to_save = "Top 10 Processes\n{}\n\n".format(data.get_top_processes(10))
            to_save += "Top 10 Paths\n{}\n\n".format(data.get_top_paths(10))
            to_save += "Top 10 Extensions\n{}\n\n".format(data.get_top_extensions(10))
            to_save += "Top 10 Folders\n{}".format(data.get_top_folders(10))
            to_save += "Top 10 Exclusions Hit\n{}".format(data.get_top_exclusions(10))
            with open(values.get("Save As"), "w") as f:
                f.write(to_save)

    window.close()


def just_process(data):
    '''
    Look at process data only.
    '''

    layout = [
        [sg.Multiline(data.get_top_processes(), size=(100, 30), key="_data")],
        [
            sg.Button("Pause", button_color=('black', '#F0F0F0')),
            sg.Button("Resume", button_color=('black', '#F0F0F0')),
            sg.FileSaveAs("Save As", button_color=('black', '#F0F0F0'), \
                          file_types=(("Log File", "*.log"),)),
            sg.Button("Reset Data", button_color=('black', '#F0F0F0')),
            sg.Button("Cancel", button_color=('black', '#F0F0F0')),
            sg.Text("Status: RUNNING", key="_running"),
        ]
    ]
    window = sg.Window("Live Top Processes", layout, location=(1, 1))
    running = True
    to_save = ""
    while True:
        event, values = window.Read(timeout=1000)
        data.update()
        if event in (None, "Cancel"):
            break
        elif event == "Pause":
            running = False
            window.Element("_running").Update("Status: PAUSED")
        elif event == "Resume":
            running = True
            window.Element("_running").Update("Status: RUNNING")
        elif event == "Reset Data":
            data.reset_data()
            window.Refresh()
        if values.get("Save As") != to_save:
            to_save = values.get("Save As")
            with open(values.get("Save As"), "w") as f:
                f.write(data.get_top_processes())
        if running:
            window.Element("_data").Update(data.get_top_processes())

    window.close()


def lpap(data):
    """
    This is the live path and process (lpap) pop-up.  Needs to be fed the data.
    """
    layout = [
        [sg.Text("CPU: {}".format(data.current_cpu), key="_cpu", size=(10, 1))],
        [
            sg.Text("Cloud Lookup Count: ", tooltip="Count of the cloud lookups since \
                starting the AMP Health Checker."),
            sg.Text("", size=(20, 1), key="_cloud_lookup_count")
        ],
        [
            sg.Text("Excluded Count: ", tooltip="Count of the scanned files that matched \
                an exclusion."),
            sg.Text("", size=(20, 1), key="_excluded_count")],
        [
            sg.Text("Cache Count: ", tooltip="Count of the files that matches a locally \
                cached hash. These don't require a cloud lookup."),
            sg.Text("", size=(20, 1), key="_cache_hit_count")
        ],
        [
            sg.Text("TETRA Scan Count: ", tooltip="Count of the files that the TETRA \
                engine scanned."),
            sg.Text("", size=(20, 1), key="_tetra_scan_count")
        ],
        [
            sg.Text("SPERO Scan Count: ", tooltip="Count of the files that the SPERO \
                engine scanned."),
            sg.Text("", size=(20, 1), key="_spero_count")
        ],
        [
            sg.Text("ETHOS Scan Count: ", tooltip="Count of the files that the ETHOS \
                engine scanned."),
            sg.Text("", size=(20, 1), key="_ethos_count")
        ],
        [
            sg.Text("Malicious Count: ", tooltip="Count of the files scanned that returned \
                a malicious disposition."),
            sg.Text("", size=(20, 1), key="_malicious_hit_count")
        ],
        [
            sg.Text("Quarantine Count: ", tooltip="Count of the files that were successfully \
                quarantined."),
            sg.Text("", size=(20, 1), key="_quarantine_count")
        ],
        [
            sg.Text("Inner File Scan Count: ", tooltip="Count of inner file scans \
                (i.e. zipped files)."),
            sg.Text("", size=(20, 1), key="_inner_file_scan")
        ],
        [sg.Text("", key="_data", size=(100, 30))],
        [
            sg.Button("Start/Resume", button_color=('black', '#F0F0F0'), key="_start_resume"),
            sg.Button("Pause", button_color=('black', '#F0F0F0')),
            sg.FileSaveAs("Save As", button_color=('black', '#F0F0F0'), \
                          file_types=(("Log File", "*.log"),)),
            sg.Button("Reset Data", button_color=('black', '#F0F0F0')),
            sg.Button("Cancel", button_color=('black', '#F0F0F0')),
            sg.Text("Status: READY", key="_running", size=(30, 1)),
        ]
    ]
    window = sg.Window("Live Path and Process", layout, location=(1, 1))
    running = False
    to_save = ""
    is_first = True
    while True:
        event, values = window.Read(timeout=1000)
        data.update()
        if event in (None, "Cancel"):
            break
        elif event == "_start_resume":
            running = True
            if is_first:
                data = lpap_data_reset(data)
                is_first = False
            window.Element("_running").Update("Status: RUNNING")
            window.Element("_start_resume").Update(disabled=True)
        elif event == "Pause":
            running = False
            window.Element("_running").Update("Status: PAUSED")
            window.Element("_start_resume").Update(disabled=False)
        elif event == "Reset Data":
            data = lpap_data_reset(data)
            window.Element("_data").Update("")
            window.Element("_cpu").Update("CPU: {}".format(data.current_cpu))
            window.FindElement('_quarantine_count').Update(data.quarantine_count)
            window.FindElement('_spero_count').Update(data.spero_count)
            window.FindElement('_ethos_count').Update(data.ethos_count)
            window.FindElement('_cloud_lookup_count').Update(data.cloud_lookup_count)
            window.FindElement('_tetra_scan_count').Update(data.tetra_scan_count)
            window.FindElement('_excluded_count').Update(data.excluded_count)
            window.FindElement('_cache_hit_count').Update(data.cache_hit_count)
            window.FindElement('_malicious_hit_count').Update(data.malicious_hit_count)
            window.FindElement('_inner_file_scan').Update(data.inner_file_count)
            window.Element("_running").Update("Status: READY")
            window.Refresh()
        if values.get("Save As") != to_save:
            to_save = values.get("Save As")
            with open(values.get("Save As"), "w") as file:
                file.write(data.convert_to_layout())
        if running:
            window.Element("_data").Update(data.convert_to_layout())
            window.Element("_cpu").Update("CPU: {}".format(data.current_cpu))
            window.FindElement('_quarantine_count').Update(data.quarantine_count)
            window.FindElement('_spero_count').Update(data.spero_count)
            window.FindElement('_ethos_count').Update(data.ethos_count)
            window.FindElement('_cloud_lookup_count').Update(data.cloud_lookup_count)
            window.FindElement('_tetra_scan_count').Update(data.tetra_scan_count)
            window.FindElement('_excluded_count').Update(data.excluded_count)
            window.FindElement('_cache_hit_count').Update(data.cache_hit_count)
            window.FindElement('_malicious_hit_count').Update(data.malicious_hit_count)
            window.FindElement('_inner_file_scan').Update(data.inner_file_count)

    window.close()


def lpap_data_reset(data):
    '''
    Reset data for lpap.
    '''
    data.spero_count = 0
    data.quarantine_count = 0
    data.cloud_lookup_count = 0
    data.tetra_scan_count = 0
    data.excluded_count = 0
    data.cache_hit_count = 0
    data.malicious_hit_count = 0
    data.inner_file_count = 0
    data.ethos_count = 0

    return data


def get_api_credentials(data, api_key='', client_id=''):
    """
    This is the section where API credentials are pulled and verified.
    """
    layout = [
        [sg.Text('Insert Client ID'), sg.InputText('', size=(20, 1))],
        [sg.Text('Insert API Key'), sg.InputText('', password_char="*", size=(20, 1))],
        [sg.Button('Save', button_color=('black', '#F0F0F0')), sg.Button('Cancel', \
                                                                         button_color=('black', '#F0F0F0'))]
    ]
    window = sg.Window("API Credentials", layout, location=(1, 1))
    while True:
        event, values = window.Read()
        logging.debug('Event - %s : Values - %s', event, values)
        if event == "Save":
            data.client_id = values[0]
            data.api_key = values[1]
            data.auth = (data.client_id, data.api_key)
            data.verify_api_creds()
            if data.api_cred_valid == False:
                layout2 = [
                    [sg.Text('Invalid Credentials')],
                    [sg.Button('OK', button_color=('black', '#F0F0F0'))]
                ]
                window2 = sg.Window('Invalid API Credentials', layout2, location=(1, 1))
                while True:
                    event2, values2 = window2.Read()
                    logging.debug('Event - %s : Values - %s', event2, values2)
                    if event2 in (None, 'OK'):
                        break
                window2.close()
            else:
                break
        elif event in (None, "Cancel"):
            break
    window.close()


def settings(data):
    """
    This is the section to display settings options.
    """
    modify_urls(data)
    # layout = [
    #     # [sg.Text('Settings'), sg.InputText('', size=(20, 1))],
    #     # update
    #     [sg.Button('URL Entry', button_color=('black', '#F0F0F0')),
    #      sg.Button('API Credential', button_color=('black', '#F0F0F0')), sg.Button('Cancel', \
    #                                                                                button_color=('black', '#F0F0F0'))]
    # ]
    # window = sg.Window("Settings", layout, location=(1, 1))
    # while True:
    #     event, values = window.Read()
    #     logging.debug('Event - %s : Values - %s', event, values)
    #     if event == "API Credential":
    #         d_instance = Data()
    #         get_api_credentials(d_instance)
    #     # update
    #     elif event == "URL Entry":
    #         modify_urls(data)
    #     elif event == "View":
    #         sg.Text("URL Endpoints: ", tooltip="List of URL endpoints i.e. cloud-ec.amp.cisco.com")
    #         [sg.Text('Insert Endpoint URL'), sg.InputText('', size=(20, 1))],
    #     elif event in (None, "Cancel"):
    #         break
    # window.close()


def api_credential(api_client_id='', api_key=''):
    """
    This is the section to edit/add new api credentials from user.
    """
    layout = [
        [sg.Text('Insert Client ID'), sg.InputText('', size=(20, 1))],
        [sg.Text('Insert API Key'), sg.InputText('', password_char="*", size=(20, 1))],
        [sg.Button('Save', button_color=('black', '#F0F0F0')), sg.Button('Cancel', button_color=('black', '#F0F0F0'))]
    ]
    window = sg.Window("API Credentials", layout, location=(1, 1))
    while True:
        event, values = window.Read()
        logging.debug('Event - %s : Values - %s', event, values)
        if event == "Save":
            api_client_id = values[0]
            api_key = values[1]
            print(api_client_id)
            print(api_key)
            window.close()
        elif event == "View":
            sg.Text("URL Endpoints: ", tooltip="List of URL endpoints i.e. cloud-ec.amp.cisco.com")
            [sg.Text('Insert Endpoint URL'), sg.InputText('', size=(20, 1))],
        elif event in (None, "Cancel"):
            break
    window.close()

def remove_urls(urls, nameUrls):
    is_found = False

    for url in urls:
        index = 0
        for item in nameUrls:
            if url == item:
                is_found = True
                break
            index = index + 1

        if is_found:
            del nameUrls[index]

    return True

def modify_urls(data):
    """
    This is the section to input new endpoint urls from user.
    """
    nameList = []
    for url in NAMADDRESSLIST:
        nameList.append(url)

    layout = [
        [sg.Text('Isolation Code:', size=(18, 1)), sg.InputText('', enable_events=True, key="-ISOLATION_CODE-", size=(50, 1))],
        [sg.Text('Policy Serial Compare:', size=(18, 1)), sg.InputText('', enable_events=True, key="-POLICY SERIAL COMPARE-", size=(50, 1))],
        [sg.Text('Tetra Compare (av64bit):', size=(18, 1)), sg.InputText('', enable_events=True, key="-TETRA_64_COMPARE-", size=(50, 1))],
        [sg.Text('Tetra Compare (av32bit):', size=(18, 1)), sg.InputText('', enable_events=True, key="-TETRA_32_COMPARE-", size=(50, 1))],
        [sg.Text('Verify API Creds:', size=(18,1)), sg.InputText('', enable_events=True, key="-VERIFY_API_CREDS-", size=(50, 1))],
        [sg.Text("Select AMP vPC URLs: ")],
        [sg.Listbox(values=nameList, size=(40, 12), key='-LIST-', select_mode='multiple', enable_events=True)],
        [sg.Text('Add AMP vPC URLs:'), sg.InputText('', enable_events=True, key="-INPUTTEXT-", size=(50, 1)),
         sg.Button('Add', key="-ADD-", button_color=('black', '#F0F0F0')),
         sg.Button('Delete', key="-DELETE-", button_color=('black', '#F0F0F0'))],
        [sg.Text('', enable_events=True, visible=False, key="-MESSAGE_TEXT-", size=(50, 1))],
        [sg.Button('Save', key="-SAVE-", button_color=('black', '#F0F0F0')),
         sg.Button('Cancel', button_color=('black', '#F0F0F0'))]
    ]
    window = sg.Window("Settings", layout, location=(20, 20))
    window.Finalize()
    window['-ADD-'].update(disabled=True)
    window['-DELETE-'].update(disabled=True)
    window['-SAVE-'].update(disabled=True)
    window['-ISOLATION_CODE-'].update(value=RESOURCES["isolation_code"])
    window['-POLICY SERIAL COMPARE-'].update(value=RESOURCES["policy_serial_compare"])
    window['-TETRA_64_COMPARE-'].update(value=RESOURCES["tetra_def_compare_64"])
    window['-TETRA_32_COMPARE-'].update(value=RESOURCES["tetra_def_compare_32"])
    window['-VERIFY_API_CREDS-'].update(value=RESOURCES["verify_api_creds"])

    while True:
        event, values = window.Read()
        logging.debug('Event - %s : Values - %s', event, values)
        if event == "-LIST-":
            selectedvalues = values["-LIST-"]
            if len(selectedvalues) > 0:
               window['-DELETE-'].update(disabled=False)
            else:
               window['-DELETE-'].update(disabled=True)
            window['-MESSAGE_TEXT-'].update(visible=False, value='')

        if event == "-INPUTTEXT-":
            window['-MESSAGE_TEXT-'].update(visible=False, value='')
            value = values["-INPUTTEXT-"]
            if not value or not re.search(regex, value):
                if value:
                    window['-MESSAGE_TEXT-'].update(visible=True, value='Invalid URL format')
                window['-ADD-'].update(disabled=True)
            else:
                window['-ADD-'].update(disabled=False)
                window['-MESSAGE_TEXT-'].update(visible=False, value='')

        if event in ["-ISOLATION_CODE-", "-POLICY SERIAL COMPARE-", "-TETRA_64_COMPARE-", "-TETRA_32_COMPARE-", "-VERIFY_API_CREDS-"]:
            window['-SAVE-'].update(disabled=False)
            window['-MESSAGE_TEXT-'].update(value='')
            window['-MESSAGE_TEXT-'].update(visible=False)

        if event == "-SAVE-":
            value1 = values["-ISOLATION_CODE-"]
            value2 = values["-POLICY SERIAL COMPARE-"]
            value3 = values["-TETRA_64_COMPARE-"]
            value4 = values["-TETRA_32_COMPARE-"]
            value5 = values["-VERIFY_API_CREDS-"]

            print(value1, value2, value3, value4, value5)
            RESOURCES["isolation_code"] = value1
            RESOURCES["policy_serial_compare"] = value2
            RESOURCES["tetra_def_compare_64"] = value3
            RESOURCES["tetra_def_compare_32"] = value4
            RESOURCES["verify_api_creds"] = value5
            NAMADDRESSLIST.clear()
            for url in nameList:
                NAMADDRESSLIST.append(url)
            save_namurls()

            window['-SAVE-'].update(disabled=True)
            window['-MESSAGE_TEXT-'].update(value='Data successfully saved')
            window['-MESSAGE_TEXT-'].update(visible=True)


        if event == "-ADD-":
            endpoint_url = values["-INPUTTEXT-"]
            print(endpoint_url)
            if re.search(regex, endpoint_url):
                print("endpoint url is:", endpoint_url)
                print("name address list before append is:", nameList)
                if not data.url_exists(endpoint_url):
                    #data.add_url(endpoint_url)
                    nameList.append(endpoint_url)
                    window.Element('-LIST-').Update(values=nameList)
                else:
                    logging.error('Duplicate URL - %s ', endpoint_url)

                print("name address list after append is:", nameList)
                window.Element('-INPUTTEXT-').Update(value='')
                window['-SAVE-'].update(disabled=False)

            else:
                layout3 = [
                    [sg.Text('Invalid URL')],
                    [sg.Button('Retry', button_color=('black', '#F0F0F0'))]
                ]
                window3 = sg.Window("Invalid URL", layout3, location=(10, 10))
                event3, values3 = window3.Read()
                if event3 == "Retry":
                    window3.close()
                    print("Invalid URL")

        if event == "-DELETE-":

            selectedvalues = values["-LIST-"] = values["-LIST-"]
            remove_urls(selectedvalues, nameList)
            window.Element('-LIST-').Update(values=nameList)

            window.Element('-INPUTTEXT-').Update(value='')
            window['-MESSAGE_TEXT-'].update(value='Urls successfully deleted')
            window['-MESSAGE_TEXT-'].update(visible=True)
            window['-SAVE-'].update(disabled=False)

        if event == "-VIEW-":
            layout = []
            for url in NAMADDRESSLIST:
                layout.append([sg.Text(url)])
            layout.append([sg.Text('')])
            layout.append([sg.Button('Close', button_color=('black', '#F0F0F0'))])
            window2 = sg.Window("Endpoint URL list", layout, location=(20, 20))
            while True:
                event, values = window2.Read()
                logging.debug('Event - %s : Values - %s', event, values)
                if event in (None, "Close"):
                    break
                elif values["-EN-0"] == True:
                    print("Items selected in List")
            window2.close()

        elif event in (None, "Cancel"):
            break
    window.close()


def connectivity(data):
    """
    This is the section where connections to the required servers are verified.
    """
    size = (30, 1)
    layout = []
    for url in data.connectivity_urls:
        layout.append([sg.Text(url, size=size, background_color="Yellow", key=url)])
    layout.append([sg.Text("Status: RUNNING", key="_conn_test_running", size=(30, 1))]),
    layout.append([sg.Button('Test Again', button_color=('black', '#F0F0F0'), key="_test_again", \
                             disabled=True), sg.Button('Cancel', button_color=('black', '#F0F0F0'))])
    window = sg.Window("AMP Connectivity", layout, location=(1, 1))
    is_first = True
    while True:
        event, values = window.Read(timeout=500)
        logging.debug('Event - %s : Values - %s', event, values)
        if is_first:
            data.connectivity_check(window)
            window.Element("_conn_test_running").Update("Status: COMPLETE")
            window.Element("_test_again").Update(disabled=False)
            is_first = False
        if event == '_test_again':
            window.Element("_test_again").Update(disabled=True)
            for url in data.connectivity_urls:
                window.Element(url).Update(background_color="Yellow")
            window.Element("_conn_test_running").Update("Status: RUNNING")
            data.connectivity_check(window)
            window.Element("_conn_test_running").Update("Status: COMPLETE")
            window.Element("_test_again").Update(disabled=False)
            window.Refresh()
        elif event in (None, 'Cancel'):
            break
    data.update()
    window.close()


def check_latest_tetra(data, window):
    '''
    Look up latest TETRA data.
    '''
    window.FindElement('_tetra_version').Update(background_color="Yellow")
    window.Element("_latest_tetra_version").Update("Checking...")
    window.FindElement('_tetra_version_button').Update(disabled=True)
    window.Refresh()
    data.tetra_def_compare()
    window.Element("_latest_tetra_version").Update(data.tetra_latest)
    window.FindElement('_tetra_version').Update(background_color=data.tetra_color)
    window.FindElement('_tetra_version_button').Update(disabled=False)
    window.Refresh()
    return


def check_latest_policy(data, window):
    '''
    Look up latest policy data.
    '''
    window.FindElement('_policy_version').Update(background_color="Yellow")
    window.FindElement('_latest_policy_version').Update("Checking...")
    window.FindElement('_policy_version_button').Update(disabled=True)
    window.Refresh()
    if not data.api_cred_valid:
        logging.debug("no auth in latest policy check")
        window.FindElement('_policy_version_button').Update(disabled=False)
        window.Element("_latest_policy_version").Update("Invalid API")
        return
    data.policy_serial_compare(data.policy_dict['policy_uuid'], data.policy_dict['policy_sn'])
    window.Element("_latest_policy_version").Update(data.policy_serial)
    window.FindElement('_policy_version').Update(background_color=data.policy_color)
    window.FindElement('_policy_version_button').Update(disabled=False)
    window.Refresh()
    return


def topips(data):
    """
    This is the section for top IP address cache queries (nfm_cache).
    """
    layout = [
        [sg.Text(data.get_top_ips(data.ip_list), size=(50, 20), key="_top_ips")],
        [sg.Button('Cancel', button_color=('black', '#F0F0F0'))]
    ]
    window = sg.Window("Top IPs", layout, location=(1, 1))

    while True:
        event, values = window.Read(timeout=1000)
        logging.debug('Event - %s : Values - %s', event, values)
        data.update()
        window.Element("_top_ips").Update(data.get_top_ips(data.ip_list))
        window.Refresh()
        if event in (None, "Cancel"):
            break
    window.close()


def engines_enabled(data):
    """
    This is the section for displaying enabled/disabled for each engine
    """
    layout = [
        [sg.Text("Engine status")],
        [sg.Checkbox('', default=True, disabled=True), sg.Text('SHA')],
        [sg.Checkbox('', default=True if (data.policy_dict['tetra'] == '1') else False, \
                     disabled=True), sg.Text('TETRA')],
        [sg.Checkbox('', default=True if (data.policy_dict['exprev_enable'] == '1') else False, \
                     disabled=True), sg.Text('Exploit Prevention')],
        [sg.Checkbox('', default=True if (data.policy_dict['DFC'] == '1') else False, \
                     disabled=True), sg.Text('Network Monitoring')],
        [sg.Checkbox('', default=True if (data.policy_dict['spp'] == '1') else False, \
                     disabled=True), sg.Text('System Process Protection')],
        [sg.Checkbox('', default=True if (data.policy_dict['ethos'] == '1') else False, \
                     disabled=True), sg.Text('ETHOS')],
        [sg.Checkbox('', default=True if (data.policy_dict['spero'] == '1') else False, \
                     disabled=True), sg.Text('SPERO')],
        [sg.Checkbox('', default=True if (data.policy_dict['orbital'] == '1') else False, \
                     disabled=True), sg.Text('Orbital')],
        [sg.Checkbox('', default=True if (data.policy_dict['endpoint_isolation'] == '1') \
            else False, disabled=True), sg.Text('Endpoint Isolation')],
        [sg.Button('OK', button_color=('black', '#F0F0F0'))]
    ]

    window = sg.Window('Engines', layout)

    while True:
        event, values = window.Read()
        logging.debug('Event - %s : Values - %s', event, values)
        if event in (None, "OK"):
            break

    window.close()


def view_exclusions(data):
    """
    This section shows the exclusions listed in the policy.xml file.
    """
    column1 = []
    for path_exclusion in data.policy_dict['path_exclusions']:
        column1.append([sg.Text(path_exclusion.split('|')[-1])])
    column2 = []
    for process_exclusion in data.policy_dict['process_exclusions']:
        column2.append([sg.Text(process_exclusion.split('|')[-3])])
    tab1_layout = [[sg.Column(column1, scrollable=True, vertical_scroll_only=True, \
                              size=(500, 400))]]
    tab2_layout = [[sg.Column(column2, scrollable=True, vertical_scroll_only=True, \
                              size=(500, 400))]]
    layout = [[sg.TabGroup([[sg.Tab('Exclusions', tab1_layout), sg.Tab('Process Exclusions', \
                                                                       tab2_layout)]])],
              [sg.Button('OK', button_color=('black', '#F0F0F0'))]]
    window = sg.Window("Exclusions", layout)

    while True:
        event, values = window.Read()
        logging.debug('Event - %s : Values - %s', event, values)
        if event in (None, 'OK'):
            break
    window.close()


def manual_sfc(data):
    """
    Pop-up for manual analysis of an SFC log.
    """
    column1 = []
    layout = [
        [sg.Text("Current SFC Log: {}".format(data.sfc_path), size=(150, 1), \
                 key="_path_display"), ],
        [sg.Button("Change SFC File", button_color=('black', '#F0F0F0')), sg.Button("Analyze", \
                                                                                    button_color=('black', '#F0F0F0')),
         sg.Button("Reset SFC File", \
                   button_color=('black', '#F0F0F0'))],
        [
            sg.Text("Cloud Lookup Count: ", tooltip="Count of the cloud lookups since starting \
                the AMP Health Checker."),
            sg.Text("", size=(20, 1), key="_cloud_lookup_count")
        ],
        [
            sg.Text("Excluded Count: ", tooltip="Count of the scanned files that matched an \
                exclusion."),
            sg.Text("", size=(20, 1), key="_excluded_count")],
        [
            sg.Text("Cache Count: ", tooltip="Count of the files that matches a locally cached \
                hash. These don't require a cloud lookup."),
            sg.Text("", size=(20, 1), key="_cache_hit_count")
        ],
        [
            sg.Text("TETRA Scan Count: ", tooltip="Count of the files that the TETRA engine \
                scanned."),
            sg.Text("", size=(20, 1), key="_tetra_scan_count")
        ],
        [
            sg.Text("SPERO Scan Count: ", tooltip="Count of the files that the SPERO engine \
                scanned."),
            sg.Text("", size=(20, 1), key="_spero_count")
        ],
        [
            sg.Text("ETHOS Scan Count: ", tooltip="Count of the files that the ETHOS engine \
                scanned."),
            sg.Text("", size=(20, 1), key="_ethos_count")
        ],
        [
            sg.Text("Malicious Count: ", tooltip="Count of the files scanned that returned a \
                malicious disposition."),
            sg.Text("", size=(20, 1), key="_malicious_hit_count")
        ],
        [
            sg.Text("Quarantine Count: ", tooltip="Count of the files that were successfully \
                quarantined."),
            sg.Text("", size=(20, 1), key="_quarantine_count")
        ],
        [
            sg.Text("Inner File Scan Count: ", tooltip="Count of inner file scans. ClamAV could \
                slow the system if scan count is high over a short period."),
            sg.Text("", size=(20, 1), key="_inner_file_scan")
        ],
        [sg.Multiline("Top 10 Processes\n" + data.get_top_processes(10), size=(100, 12), \
                      key="_top_processes"),
         sg.Multiline("Top 10 Paths\n" + data.get_top_paths(10), size=(100, 12), \
                      key="_top_paths")],
        [sg.Multiline("Top 10 Extensions\n" + data.get_top_extensions(10), size=(100, 12), \
                      key="_top_extensions"),
         sg.Multiline("Top 10 Folders\n" + data.get_top_folders(10), size=(100, 12), \
                      key="_top_folders")],
        [sg.Multiline("Top 10 Exclusions Hit\n" + data.get_top_exclusions(10), size=(100, 12), \
                      key="_top_exclusions")],
        [
            sg.FileSaveAs("Save As", button_color=('black', '#F0F0F0'), \
                          file_types=(("Log File", "*.log"),)),
            sg.Button("Cancel", button_color=('black', '#F0F0F0')),
        ]
    ]

    window = sg.Window("Manual SFC Analysis", layout, location=(5, 5))

    while True:
        event, values = window.Read()
        logging.debug('Event - %s : Values - %s', event, values)
        if event in (None, 'OK', 'Cancel'):
            break
        elif event == "Change SFC File":
            new_sfc_file = sg.PopupGetFile(
                title="SFC Log",
                message="Choose New SFC.log",
                default_path=data.sfc_path,
                initial_folder="{}/{}".format(data.root_path, data.version))
            data.sfc_path = new_sfc_file
            window.Element("_path_display").Update("Current SFC Log: {}".format(data.sfc_path))
            window.Refresh()
        elif event == "Analyze":
            with open(data.sfc_path) as file:
                data.last_log_line = file.readlines()[0]
            data.update()
            window.FindElement('_quarantine_count').Update(data.quarantine_count)
            window.FindElement('_spero_count').Update(data.spero_count)
            window.FindElement('_ethos_count').Update(data.ethos_count)
            window.FindElement('_cloud_lookup_count').Update(data.cloud_lookup_count)
            window.FindElement('_tetra_scan_count').Update(data.tetra_scan_count)
            window.FindElement('_excluded_count').Update(data.excluded_count)
            window.FindElement('_cache_hit_count').Update(data.cache_hit_count)
            window.FindElement('_malicious_hit_count').Update(data.malicious_hit_count)
            window.FindElement('_inner_file_scan').Update(data.inner_file_count)
            window.FindElement('_top_processes').Update("Top 10 Processes\n" + \
                                                        data.get_top_processes(10))
            window.FindElement('_top_paths').Update("Top 10 Paths\n" + data.get_top_paths(10))
            window.FindElement('_top_extensions').Update("Top 10 Extensions\n" + \
                                                         data.get_top_extensions(10))
            window.FindElement('_top_folders').Update("Top 10 Folders\n" + data.get_top_folders(10))
            window.FindElement('_top_exclusions').Update("Top 10 Exclusions Hit\n" + data.get_top_exclusions(10))
        elif event == "Reset SFC File":
            data.sfc_path = "{}/{}/sfc.exe.log".format(data.root_path, data.version)
            window.Element("_path_display").Update("Current SFC Log: {}".format(data.sfc_path))
            window.Refresh()
    window.close()


def diag_failed_popup():
    '''
    Provide feedback for unsuccessful diagnostic gathering.
    '''
    layout = [
        [sg.Text("The diagnostic gathering failed.  Please do the following:")],
        [sg.Text("From the Start Menu, Run 'Support Diagnostic Tool'.  This will drop a .7z file \
            on the Desktop after a few seconds.")],
        [sg.Text("Also, from the directory from where this Health Check tool is executed, gather \
            the amp_health_checker_log.log file.")],
        [sg.Text("The .7z and .log file are the two needed Diagnostic Files.")],
        [sg.OK()],
    ]

    window = sg.Window("Diagnostic Error", layout)

    while True:
        event, values = window.Read()
        logging.debug('Event - %s : Values - %s', event, values)
        if event in (None, 'OK', 'Cancel'):
            break
    window.close()
    return


if __name__ == "__main__":
    d = Data()
    diag_failed_popup()
