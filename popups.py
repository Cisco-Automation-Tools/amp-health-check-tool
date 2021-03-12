"""
This section is for all the popup GUIs off the main page.
"""
# update
import json
import logging
import re
from textwrap import wrap
import PySimpleGUI as sg
from schema import SchemaError

# update
from amp_settings import Config, PrivateConfig, SettingsManager
from config_schema import config_schema
from config_schema import valid_url_re as regex

disable_color = "gray"
enable_color = "black"


def _(msg: list):
    return "\n".join(wrap(msg))


def analysis(data, settings_manager):
    """
    Run quick analysis on the system.
    """
    data.update(settings_manager)
    layout = [
        [sg.Multiline("Top 10 Processes\n" + data.get_top_processes(10),
                      size=(200, 12), key="_top_processes")],
        [sg.Multiline("Top 10 Paths\n" + data.get_top_paths(10),
                      size=(200, 12), key="_top_paths")],
        [sg.Multiline("Top 10 Extensions\n" + data.get_top_extensions(10),
                      size=(200, 12), key="_top_extensions")],
        [sg.Multiline("Top 10 Folders\n" + data.get_top_folders(10),
                      size=(200, 12), key="_top_folders")],
        [sg.Multiline("Top 10 Exclusions Hit\n" + data.get_top_exclusions(10),
                      size=(200, 12), key="_top_exclusions")],
        [
            sg.FileSaveAs("Save As", button_color=('black', '#F0F0F0'),
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
        data.update(settings_manager)
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


def just_process(data, settings_manager):
    """
    Look at process data only.
    """

    layout = [
        [sg.Multiline(data.get_top_processes(), size=(100, 30), key="_data")],
        [
            sg.Button("Pause", button_color=('black', '#F0F0F0')),
            sg.Button("Resume", button_color=('black', '#F0F0F0')),
            sg.FileSaveAs("Save As", button_color=('black', '#F0F0F0'),
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
        data.update(settings_manager)
        if event in (None, "Cancel"):
            break
        elif event == "Pause":
            running = False
            window.Element("_running").Update("Status: PAUSED")
        elif event == "Resume":
            running = True
            window.Element("_running").Update("Status: RUNNING")
        elif event == "Reset Data":
            data.reset_data(settings_manager)
            window.Refresh()
        if values.get("Save As") != to_save:
            to_save = values.get("Save As")
            with open(values.get("Save As"), "w") as f:
                f.write(data.get_top_processes())
        if running:
            top = data.get_top_processes()
            window.Element("_data").Update(value=top)

    window.close()


def lpap(data, settings_manager):
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
            sg.FileSaveAs("Save As", button_color=('black', '#F0F0F0'),
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
        data.update(settings_manager)
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
    """
    Reset data for lpap.
    """
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


def get_api_credentials(data, settings_manager):
    """
    This is the section where API credentials are pulled and verified.
    """
    layout = [
        [sg.Text('Insert Client ID'), sg.InputText('', key="-ID-", size=(20, 1))],
        [sg.Text('Insert API Key'), sg.InputText('', key="-KEY-", password_char="*", size=(20, 1))],
        [sg.Button('Save', button_color=('black', '#F0F0F0')), sg.Button('Cancel',
                                                                         button_color=('black', '#F0F0F0'))]
    ]
    window = sg.Window("API Credentials", layout, location=(1, 1))
    while True:
        event, values = window.Read()
        logging.debug('Event - %s : Values - %s', event, values)
        if event == "Save":
            settings_manager.client_id = values["-ID-"]
            settings_manager.api_key = values["-KEY-"]
            data.verify_api_creds(settings_manager)
            if not data.api_cred_valid:
                layout2 = [
                    [sg.Text(_(data.api_cred_msg))],
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


def place(elem):
    """
    Places element provided into a Column element so that its placement in the layout is retained.
    :param elem: the element to put into the layout
    :return: A column element containing the provided element
    """
    return sg.Column([[elem]], pad=(0, 0))


def settings(settings_manager: SettingsManager):
    """
    This is the section to display settings options.
    """
    rollback_config = settings_manager.current
    listbox = sg.Listbox(values=[], size=(80, 12), key='-LIST-', select_mode='multiple', enable_events=True, )
    layout = [
        [sg.Text('Mode:'), sg.Text('', key="-MODE-", size=(25, 1), font='Helvetica 10 bold'),
         sg.Button('Private', size=(7, 1), key="-PRIVATE-", button_color=('black', '#F0F0F0')),
         sg.Button('NAM', size=(7, 1), key="-NAM-", button_color=('black', '#F0F0F0')),
         sg.Button('EU', size=(7, 1), key="-EU-", button_color=('black', '#F0F0F0')),
         sg.Button('APJC', size=(7, 1), key="-APJC-", button_color=('black', '#F0F0F0'))],
        [sg.Text('_' * 80)],
        [sg.Text('AMP Console Hostname:', size=(18, 1)),
         sg.InputText(enable_events=True, key="-AMP_CONSOLE_HOSTNAME-", size=(50, 1))],
        [sg.Text('_' * 80)],

        [sg.Text('Isolation URL:', size=(18, 1)),
         sg.InputText(disabled=True, key="-ISOLATION_CODE-", size=(50, 1),
                      text_color=disable_color)],
        [sg.Text('Policy URL:', size=(18, 1)),
         sg.InputText(disabled=True, key="-POLICY SERIAL COMPARE-", size=(50, 1),
                      text_color=disable_color)],
        [sg.Text('Tetra 32bit URL:', size=(18, 1)),
         sg.InputText(disabled=True, key="-TETRA_32_COMPARE-", size=(50, 1),
                      text_color=disable_color)],
        [sg.Text('Tetra 64bit URL:', size=(18, 1)),
         sg.InputText(disabled=True, key="-TETRA_64_COMPARE-", size=(50, 1),
                      text_color=disable_color)],
        [sg.Text('Verify API Creds URL:', size=(18, 1)),
         sg.InputText(disabled=True, key="-VERIFY_API_CREDS-", size=(50, 1),
                      text_color=disable_color)],
        [sg.Text('' * 80)],

        [sg.Text("AMP Endpoints", size=(80, 1), text_color='white', font='Helvetica 10 bold', justification="center")],
        [listbox],
        [place(sg.InputText(enable_events=True, key="-INPUTTEXT-", size=(35, 1))),
         place(sg.Button('Add', size=(7, 1), key="-ADD-", button_color=('black', '#F0F0F0'))),
         place(sg.Button('Delete', size=(7, 1), key="-DELETE-", button_color=('black', '#F0F0F0')))],
        [sg.Text('' * 80)],
        [sg.Text('', enable_events=True, visible=False, key="-MESSAGE_TEXT-", size=(50, 1))],
        [sg.Button('Save', size=(7, 1), key="-SAVE-", button_color=('black', '#F0F0F0')),
         sg.Button('Cancel', size=(7, 1), button_color=('black', '#F0F0F0')), sg.Text(' ' * 75),
         sg.Button('Import', size=(7, 1), key="-IMPORT-", button_color=('black', '#F0F0F0'))]
    ]
    window = sg.Window("Settings", layout, location=(20, 20), size=(600, 660), margins=(20, 20))
    window = window.Finalize()

    window['-DELETE-'].update(disabled=True)
    window['-SAVE-'].update(disabled=False)
    populate_window(window,
                    settings_manager.current.mode,
                    settings_manager.current.amp_console_hostname,
                    settings_manager.current.resources,
                    settings_manager.current.endpoints,
                    )

    while True:
        event, values = window.Read()
        logging.debug('Event - %s : Values - %s', event, values)

        if event == "-LIST-":
            selected_values = listbox.get_indexes()
            if len(selected_values) > 0:
                window['-DELETE-'].update(disabled=False)
            else:
                window['-DELETE-'].update(disabled=True)
            window['-MESSAGE_TEXT-'].update(visible=False, value='')

        if event == "-AMP_CONSOLE_HOSTNAME-":
            amp_console_hostname_url = values["-AMP_CONSOLE_HOSTNAME-"]
            if isinstance(amp_console_hostname_url, str) and regex.search(amp_console_hostname_url):
                window["-ISOLATION_CODE-"].update(value=amp_console_hostname_url + "/v1/computers/{}/isolation")
                window["-POLICY SERIAL COMPARE-"].update(value=amp_console_hostname_url + "/v1/policies/{}")
                window["-TETRA_32_COMPARE-"].update(value=amp_console_hostname_url + "/av32bit/versions.id")
                window["-TETRA_64_COMPARE-"].update(value=amp_console_hostname_url + "/av64bit/versions.id")
                window["-VERIFY_API_CREDS-"].update(value=amp_console_hostname_url + "/v1/version")
                window['-MESSAGE_TEXT-'].update(visible=True, value='')
            else:
                window["-ISOLATION_CODE-"].update(value="")
                window["-POLICY SERIAL COMPARE-"].update(value="")
                window["-TETRA_64_COMPARE-"].update(value="")
                window["-TETRA_32_COMPARE-"].update(value="")
                window["-VERIFY_API_CREDS-"].update(value="")
                window['-MESSAGE_TEXT-'].update(visible=True, value='Invalid URL format')

        if event == "-IMPORT-":
            validated_data = import_popup()
            if validated_data:
                mode = validated_data["MODE"]
                if mode == "PRIVATE":
                    imported_config = PrivateConfig(validated_data, mode)
                else:
                    imported_config = Config(validated_data, mode)
                logging.debug(imported_config)
                populate_window(window,
                                imported_config.mode,
                                imported_config.amp_console_hostname,
                                imported_config.resources,
                                imported_config.endpoints
                                )

        if event in {"-EU-", "-NAM-", "-APJC-", "-PRIVATE-"}:
            logging.debug("SWITCHING MODES NOW")
            settings_manager.switch_config(settings_manager.configs[event])

            window['-ADD-'].update(disabled=True)
            window['-SAVE-'].update(disabled=False)
            window['-MESSAGE_TEXT-'].update(value='', visible=True)

            populate_window(window,
                            settings_manager.current.mode,
                            settings_manager.current.amp_console_hostname,
                            settings_manager.current.resources,
                            settings_manager.current.endpoints
                            )
            logging.debug("SWITCHING MODES DONE")

        if event == "-SAVE-":
            endpoints = window["-LIST-"].get_list_values()
            try:
                settings_manager.save_to_disk(values, endpoints)
                rollback_config = settings_manager.current
                window['-MESSAGE_TEXT-'].update(value='Data successfully saved')
                window['-MESSAGE_TEXT-'].update(visible=True)
            except SchemaError as e:
                sg.Popup(f"Unable to save:\n{e.code}")

        if event == "-INPUTTEXT-":
            value = values["-INPUTTEXT-"]
            if isinstance(value, str) and regex.search(value):
                window['-MESSAGE_TEXT-'].update(visible=False, value='')
                window['-ADD-'].update(disabled=False)
            else:
                window['-MESSAGE_TEXT-'].update(visible=True, value='Invalid URL format')
                window['-ADD-'].update(disabled=True)

        if event == "-ADD-":
            endpoint_url = values["-INPUTTEXT-"]
            if regex.search(endpoint_url):
                listbox_data = listbox.get_list_values()
                listbox_data.append(endpoint_url)
                logging.debug(f"ADD LIST:")
                populate_endpoint_list(window,
                                       settings_manager.current.mode,
                                       listbox_data)
                window.Element('-INPUTTEXT-').update(value='')
                window['-SAVE-'].update(disabled=False)

        if event == "-DELETE-":
            sel = listbox.get_indexes()
            listbox_data = listbox.get_list_values()
            for index in sel[::-1]:
                listbox_data.pop(index)
            populate_endpoint_list(window,
                                   settings_manager.current.mode,
                                   listbox_data)

            window['-MESSAGE_TEXT-'].update(value='Urls successfully deleted')
            window['-MESSAGE_TEXT-'].update(visible=True)
            window['-SAVE-'].update(disabled=False)

        if event in {sg.WIN_CLOSED, None, "Cancel"}:
            settings_manager.current = rollback_config
            break
    window.close()


def populate_endpoint_list(window, mode, endpoints):
    window["-LIST-"].update(disabled=False)
    if re.search("eu|nam|apjc", mode, re.I):
        window["-LIST-"].update(values=endpoints)
        window["-LIST-"].update(disabled=True)
    else:
        window["-LIST-"].update(values=endpoints, disabled=False)
        window["-LIST-"].update(disabled=False)


def populate_window(window, mode, amp_console_hostname, resource, endpoints):
    logging.debug("{}".format("\n".join(map(str, [mode, amp_console_hostname, resource, endpoints]))))
    if re.search("eu|nam|apjc", mode, re.I):
        window['-INPUTTEXT-'].update(visible=False, disabled=True)
        window['-ADD-'].update(visible=False, disabled=True)
        window['-DELETE-'].update(visible=False, disabled=True)
        window['-AMP_CONSOLE_HOSTNAME-'].update(disabled=False)
        window['-AMP_CONSOLE_HOSTNAME-'].update(value="")
        window['-AMP_CONSOLE_HOSTNAME-'].update(visible=False,
                                                disabled=True,
                                                text_color=disable_color
                                                )

    else:
        window['-INPUTTEXT-'].update(visible=True, disabled=False)
        window['-ADD-'].update(visible=True, disabled=False)
        window['-DELETE-'].update(visible=True, disabled=False)
        window["-AMP_CONSOLE_HOSTNAME-"].update(visible=True,
                                                value=amp_console_hostname,
                                                disabled=False,
                                                text_color=enable_color
                                                )

    populate_endpoint_list(window, mode, endpoints)

    window["-IMPORT-"].update(disabled=False)
    window['-SAVE-'].update(disabled=False)

    window["-MODE-"].update(value=mode)

    window["-ISOLATION_CODE-"].update(value=resource["isolation_code"], disabled=False)
    window["-POLICY SERIAL COMPARE-"].update(value=resource["policy_serial_compare"], disabled=False)
    window["-TETRA_64_COMPARE-"].update(value=resource["tetra_def_compare_64"], disabled=False)
    window["-TETRA_32_COMPARE-"].update(value=resource["tetra_def_compare_32"], disabled=False)
    window["-VERIFY_API_CREDS-"].update(value=resource["verify_api_creds"], disabled=False)

    window["-ISOLATION_CODE-"].update(disabled=True)
    window["-POLICY SERIAL COMPARE-"].update(disabled=True)
    window["-TETRA_64_COMPARE-"].update(disabled=True)
    window["-TETRA_32_COMPARE-"].update(disabled=True)
    window["-VERIFY_API_CREDS-"].update(disabled=True)


def import_popup():
    import_layout = [
        [sg.T("")], [sg.Text("Choose a file: "), sg.Input(), sg.FileBrowse(key="-FILE-")],
        [sg.Text('' * 80)],
        [
            sg.Button('OK', key="-OK-", size=(7, 1), button_color=('black', '#F0F0F0')),
            sg.Button('Cancel', key="-ICANCEL-", size=(7, 1), button_color=('black', '#F0F0F0'))
        ],
        [sg.Text('', enable_events=True, visible=False, key="-MESSAGE_TEXT-", size=(50, 1))],
    ]

    ###Building Window
    window = sg.Window('My File Browser', import_layout, size=(600, 150)).finalize()

    while True:
        event, values = window.read()
        if event in {sg.WIN_CLOSED, "-ICANCEL-", "Exit"}:
            validated_data = None
            break
        elif event == "-OK-":
            try:
                with open(values["-FILE-"]) as fp:
                    data = json.load(fp)
                validated_data = config_schema.validate(data)
                logging.debug(validated_data)
                break
            except json.decoder.JSONDecodeError as e:
                errmsg = '%s: line %d column %d (char %d)' % (e.msg, e.lineno, e.colno, e.pos)
                window['-MESSAGE_TEXT-'].update(visible=True, value=f'Invalid file chosen: Invalid JSON:\n{errmsg}')
            except SchemaError as e:
                window['-MESSAGE_TEXT-'].update(visible=True, value=f'Invalid file chosen: Schema Error:\n{e.code}')
            except Exception as e:
                window['-MESSAGE_TEXT-'].update(visible=True, value=f'Invalid file chosen: UNKNOWN ERROR: {str(e)}')

    window.close()
    return validated_data


def connectivity(data, settings_manager):
    """
    This is the section where connections to the required servers are verified.
    """
    size = (30, 1)
    layout = []
    for url in settings_manager.current.endpoints:
        layout.append([sg.Text(url, size=size, background_color="Yellow", key=url)])
    layout.append([sg.Text("Status: RUNNING", key="_conn_test_running", size=(30, 1))]),
    layout.append([sg.Button('Test Again', button_color=('black', '#F0F0F0'), key="_test_again",
                             disabled=True), sg.Button('Cancel', button_color=('black', '#F0F0F0'))])
    window = sg.Window("AMP Connectivity", layout, location=(1, 1))
    is_first = True
    while True:
        event, values = window.Read(timeout=500)
        logging.debug('Event - %s : Values - %s', event, values)
        if is_first:
            data.connectivity_check(window, settings_manager)
            window.Element("_conn_test_running").Update("Status: COMPLETE")
            window.Element("_test_again").Update(disabled=False)
            is_first = False
        if event == '_test_again':
            window.Element("_test_again").Update(disabled=True)
            for url in settings_manager.current.endpoints:
                window.Element(url).Update(background_color="Yellow")
            window.Element("_conn_test_running").Update("Status: RUNNING")
            data.connectivity_check(window, settings_manager)
            window.Element("_conn_test_running").Update("Status: COMPLETE")
            window.Element("_test_again").Update(disabled=False)
            window.Refresh()
        elif event in (None, 'Cancel'):
            break
    data.update(settings_manager)
    window.close()


def check_latest_tetra(data, window, settings_manager):
    """
    Look up latest TETRA data.
    """
    window.FindElement('_tetra_version').Update(background_color="Yellow")
    window.Element("_latest_tetra_version").Update("Checking...")
    window.FindElement('_tetra_version_button').Update(disabled=True)
    window.Refresh()
    success, msg = data.tetra_def_compare(settings_manager)
    window.Element("_latest_tetra_version").Update(data.tetra_latest)
    window.FindElement('_tetra_version').Update(background_color=data.tetra_color)
    if not success:
        sg.Popup(_(msg))
    window.FindElement('_tetra_version_button').Update(disabled=False)
    window.Refresh()
    return


def check_latest_policy(data, window, settings_manager):
    """
    Look up latest policy data.
    """
    window.FindElement('_policy_version').Update(background_color="Gray")
    window.FindElement('_latest_policy_version').Update("Checking...")
    window.FindElement('_policy_version_button').Update(disabled=True)
    window.Refresh()
    success, msg = data.policy_serial_compare(data.policy_dict['policy_uuid'],
                                              data.policy_dict['policy_sn'],
                                              settings_manager)
    window.Element("_latest_policy_version").Update(data.policy_serial)
    window.FindElement('_policy_version').Update(background_color=data.policy_color)
    if not success:
        sg.Popup(_(msg))
    window.FindElement('_policy_version_button').Update(disabled=False)
    window.Refresh()
    return


def topips(data, settings_manager):
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
        data.update(settings_manager)
        window.Element("_top_ips").Update(data.get_top_ips(data.ip_list))
        window.Refresh()
        if event in (None, "Cancel"):
            break
    window.close()


def engines_enabled(data):
    """
    This is the section for displaying enabled/disabled for each engine
    """

    def r_or_g(expression):
        return "#28a745" if expression else "gray"

    pd = data.policy_dict
    layout = [
        [sg.Text("Engine status")],
        [sg.Text('   ', background_color=r_or_g(True), key="SHA"),
         sg.Text('SHA')],
        [sg.Text('   ', background_color=r_or_g(pd['tetra'] == '1'), key="TETRA"),
         sg.Text('TETRA')],
        [sg.Text('   ', background_color=r_or_g(pd['exprev_enable'] == '1'), key="EXPREV"),
         sg.Text('Exploit Prevention')],
        [sg.Text('   ', background_color=r_or_g(pd['DFC'] == '1'), key="DFC"),
         sg.Text('Network Monitoring')],
        [sg.Text('   ', background_color=r_or_g(pd['spp'] == '1'), key="SPP"),
         sg.Text('System Process Protection')],
        [sg.Text('   ', background_color=r_or_g(pd['ethos'] == '1'), key="ETHOS"),
         sg.Text('ETHOS')],
        [sg.Text('   ', background_color=r_or_g(pd['spero'] == '1'), key="SPERO"),
         sg.Text('SPERO')],
        [sg.Text('   ', background_color=r_or_g(pd['orbital'] == '1'), key="ORBITAL"),
         sg.Text('Orbital')],
        [sg.Text('   ', background_color=r_or_g(pd['endpoint_isolation'] == '1'), key="ISO"),
         sg.Text('Endpoint Isolation')],
        [sg.Button('OK', button_color=('black', '#F0F0F0'))]
    ]

    window = sg.Window('Engines', layout).finalize()

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
    tab1_layout = [[sg.Column(column1, scrollable=True, vertical_scroll_only=True,
                              size=(500, 400))]]
    tab2_layout = [[sg.Column(column2, scrollable=True, vertical_scroll_only=True,
                              size=(500, 400))]]
    layout = [[sg.TabGroup([[sg.Tab('Exclusions', tab1_layout), sg.Tab('Process Exclusions',
                                                                       tab2_layout)]])],
              [sg.Button('OK', button_color=('black', '#F0F0F0'))]]
    window = sg.Window("Exclusions", layout)

    while True:
        event, values = window.Read()
        logging.debug('Event - %s : Values - %s', event, values)
        if event in (None, 'OK'):
            break
    window.close()


def manual_sfc(data, settings_manager):
    """
    Pop-up for manual analysis of an SFC log.
    """
    column1 = []
    layout = [
        [sg.Text("Current SFC Log: {}".format(data.sfc_path), size=(150, 1),
                 key="_path_display"), ],
        [sg.Button("Change SFC File", button_color=('black', '#F0F0F0')), sg.Button("Analyze",
                                                                                    button_color=('black', '#F0F0F0')),
         sg.Button("Reset SFC File",
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
        [sg.Multiline("Top 10 Processes\n" + data.get_top_processes(10), size=(100, 12),
                      key="_top_processes"),
         sg.Multiline("Top 10 Paths\n" + data.get_top_paths(10), size=(100, 12),
                      key="_top_paths")],
        [sg.Multiline("Top 10 Extensions\n" + data.get_top_extensions(10), size=(100, 12),
                      key="_top_extensions"),
         sg.Multiline("Top 10 Folders\n" + data.get_top_folders(10), size=(100, 12),
                      key="_top_folders")],
        [sg.Multiline("Top 10 Exclusions Hit\n" + data.get_top_exclusions(10), size=(100, 12),
                      key="_top_exclusions")],
        [
            sg.FileSaveAs("Save As", button_color=('black', '#F0F0F0'),
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
            data.update(settings_manager)
            window.FindElement('_quarantine_count').Update(data.quarantine_count)
            window.FindElement('_spero_count').Update(data.spero_count)
            window.FindElement('_ethos_count').Update(data.ethos_count)
            window.FindElement('_cloud_lookup_count').Update(data.cloud_lookup_count)
            window.FindElement('_tetra_scan_count').Update(data.tetra_scan_count)
            window.FindElement('_excluded_count').Update(data.excluded_count)
            window.FindElement('_cache_hit_count').Update(data.cache_hit_count)
            window.FindElement('_malicious_hit_count').Update(data.malicious_hit_count)
            window.FindElement('_inner_file_scan').Update(data.inner_file_count)
            window.FindElement('_top_processes').Update("Top 10 Processes\n" +
                                                        data.get_top_processes(10))
            window.FindElement('_top_paths').Update("Top 10 Paths\n" + data.get_top_paths(10))
            window.FindElement('_top_extensions').Update("Top 10 Extensions\n" +
                                                         data.get_top_extensions(10))
            window.FindElement('_top_folders').Update("Top 10 Folders\n" + data.get_top_folders(10))
            window.FindElement('_top_exclusions').Update("Top 10 Exclusions Hit\n" + data.get_top_exclusions(10))
        elif event == "Reset SFC File":
            data.sfc_path = "{}/{}/sfc.exe.log".format(data.root_path, data.version)
            window.Element("_path_display").Update("Current SFC Log: {}".format(data.sfc_path))
            window.Refresh()
    window.close()


def diag_failed_popup(failures):
    """
    Provide feedback for unsuccessful diagnostic gathering.
    """
    copy_fail = [sg.Text("From the directory from where this Health Check tool is executed, gather "
                         "the amp_health_checker_log.log file.")] if failures[0] else []
    support_tool_fail = [sg.Text("From the Start Menu, Run 'Support Diagnostic Tool'.This will drop a .7z file "
                                 "on the Desktop after a few seconds.")] if failures[1] else []

    layout = [
        [sg.Text("The diagnostic gathering failed.  Please do the following:")],
        support_tool_fail,
        copy_fail,
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
