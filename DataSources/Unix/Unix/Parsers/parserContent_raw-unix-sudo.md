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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[\w.\-]+)""",
    """exabeam_host=([^=]+@\s*)?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({dest_host}[^\s]+))""",
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
  DupFields=["directory->process_directory"]
}
```