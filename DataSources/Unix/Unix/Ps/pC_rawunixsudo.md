#### Parser Content
```Java
{
Name = raw-unix-sudo
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """sudo:""", """; USER""","""; COMMAND""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\w{3} \d{1,2}, \d\d\d\d, \d{1,2}:\d{1,2}:\d{1,2} (?i)(am|pm))""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(gcs-topic|({host}[\w.\-]{1,2000}))""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(gcs-topic|(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({dest_host}[^\s]{1,2000})))""",
    """"agent_hostname":"({host}[^"]{1,200})"""",
    """"agent_hostname":"(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({dest_host}[^"]{1,2000}))"""",
    """({host}[\w\.\-]{1,2000})?:?\s{0,100}sudo:""",
    """"agent":\{"id":"({agent_id}\d{1,100})"""",
    """"agent":\{"name":"[^"]{0,2000}","id":"({agent_id}\d{1,100})"""",
    """({event_code}sudo):\s{1,100}(?:\[[^]]{1,2000}\])?\s{0,100}(({domain}[^\\:;]{1,2000})\\+)?({user}[^\s:]{1,2000}).+?USER\\*=({account}[^;\s]{1,2000})""",
    """\WPWD=({directory}[^\s;]{1,2000})""",
    """\WCOMMAND=({process}([^\s]{1,2000}[\\\/]{1,2000})?({process_name}[^;\\\/\s]{1,2000}))\s(?:|;|$)""",
    """\WCOMMAND=({command_line}[^;"]{1,2000})("|\s(?:|;|$))""",
    """"description":"({event_name}[^"]{1,2000})"""",
    """"level":({level}[^",]{1,2000})""",
    """"groups":\[({groups}[^\]]{1,2000})""",
    """"pci_dss":\[({pci_dss}[^\]]{1,2000})""",
    """"cluster":\{[^\{\}]{1,2000}?"name":"({cluster_name}[^"]{1,2000})"""",
    """"host":"({wazuh_manager}[^"]{1,2000})"""",
  ]
  DupFields=["directory->process_directory"]
}
```