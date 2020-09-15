#### Parser Content
```Java
{
Name = iptables-network-connection-failed
  Vendor = IPTables
  Product = IPTables
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """ kernel: """, """ DENY """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """({host}[\w.\-]+)\s+kernel:\s""",
    """\sIN=({src_interface}[^=]+?)(\s+\w+=|\s*$)""",
    """\sOUT=({dest_interface}[^=]+?)(\s+\w+=|\s*$)""",
    """\sMAC=({src_mac}[^=]+?)(\s+\w+=|\s*$)""",
    """\sSRC=({src_ip}[a-fA-F\d.:]+)""",
    """\sDST=({dest_ip}[a-fA-F\d.:]+)""",
    """\sPROTO=({protocol}[^=]+?)(\s+\w+=|\s*$)""",
    """\sSPT=({src_port}\d+)""",
    """\sDPT=({dest_port}\d+)""",
  ]
}

{
  Name = netwrix-file-activity
  Vendor = Netwrix
  Product = Netwrix Auditor
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """<EventRecordID>""", """ Action : """, """ ObjectType : """, """ What : """ ]
  Fields = [
    """When\s*:\s*({time}\d+-\d+-\d+T\d+:\d+:\d+Z)""",
    """<Computer>({host}[\w\-.]+)""",
    """>({event_code}\d+)<\/EventID>""",
    """<EventRecordID>({record_id}.+?)<\/EventRecordID>""",
    """Action\s*:\s*({accesses}.+?)\s*Message\s*:""",
    """Where\s*:\s*({dest_host}[\w\-.]+)""",
    """ObjectType\s*:\s*({file_type}.+?)\s*Who\s*:""",
    """Who\s*:\s*(({domain}[^\\\s]+)\\+)?(system|({user}[^\\\s]+))""",
    """What\s*:\s*(|({file_path}({file_parent}[^"]*?)[\\\/]*({file_name}[^\\"]+?(\.({file_ext}[^\\\.\s"]+))?)))\s*When\s*:""",
    """Workstation\s*:\s*(|({src_ip}[A-Fa-f:\d.]+))\s*Details\s*:""",
  ]
}
```