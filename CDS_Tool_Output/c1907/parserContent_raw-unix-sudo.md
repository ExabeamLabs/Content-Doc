#### Parser Content
```Java
{
Name = raw-unix-sudo
  Vendor = Unix
  Lms = Direct
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """sudo:""", """; USER""","""; COMMAND""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d+:\d+) \S+ sudo:""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+[+-]\d+)""",
    """exabeam_host=([^=]+@\s*)?({host}[\w.\-]+)""",
    """({host}[\w\.\-]+)?:?\s*sudo:""",
    """"agent":\{"id":"({agent_id}\d+)"""",
    """"agent":\{"name":"[^"]*","id":"({agent_id}\d+)"""",
    """({event_code}sudo):\s+(?:\[[^]]+\])?\s*(({domain}[^\\:;]+)\\+)?({user}[^\s:]+).+?USER\\*=({account}[^;\s]+)""",
    """\WPWD=({directory}[^\s;]+)""",
    """\WCOMMAND=({process}([^\s]+[\\\/]+)?({process_name}[^;\\\/\s]+))\s(?:|;|$)""",
    """\WCOMMAND=({command_line}[^;"]+)("|\s(?:|;|$))""",
    """"description":"({event_name}[^"]+)"""",
    """"level":({level}[^",]+)""",
    """"groups":\[({groups}[^\]]+)""",
    """"pci_dss":\[({pci_dss}[^\]]+)""",
    """"cluster":\{[^\{\}]+?"name":"({cluster_name}[^"]+)"""",
    """"host":"({wazuh_manager}[^"]+)"""",
  ]
  DupFields=["host->dest_host","directory->process_directory"]
}
```