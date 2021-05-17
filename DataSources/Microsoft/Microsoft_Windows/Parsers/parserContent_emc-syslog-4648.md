#### Parser Content
```Java
{
Name = emc-syslog-4648
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "__li_source_path=", "A logon was attempted using explicit credentials","""eventid="4648"""" ]
  Fields = [ 
    """({event_name}A logon was attempted using explicit credentials)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """__li_source_path="({host}[^"]{1,2000})"""",
    """({event_code}4648)""",
    """Subject:\s{1,100}Security ID:\s{1,100}({user_sid}[^\s]{1,2000})""",
    """Subject:.+?Account\sName:\s{1,100}(?:-|({user}.+?))\s{1,100}Account\sDomain:\s{1,100}(?:-|({domain}[^\s]{1,2000}))\s{1,100}Logon\sID:\s{1,100}({logon_id}[^\s]{1,2000})\s{1,100}""",
    """Used:\s{1,100}Account\sName:\s{1,100}({account}[^\s]{1,2000})\s{1,100}Account\sDomain:\s{1,100}({account_domain}[^\s]{1,2000})\s{1,100}"""
    """Target\sServer\sName:\s{1,100}({dest_host}[^\s]{1,2000})""",
    """Process ID:\s{1,100}({process_id}\w+)\s{1,100}Process Name:""",
    """Process Name:\s{1,100}(?: |({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?)))\s{1,100}Network Information:""",
    """Network Address:\s{1,100}(?:-|({src_ip}[\d\.]{1,2000}))""",
    """Additional Information:\s{1,100}({dest_service}[^\s]{1,2000})\s{1,100}Process Information:"""
  ]
  DupFields = ["directory->process_directory"]
}
```