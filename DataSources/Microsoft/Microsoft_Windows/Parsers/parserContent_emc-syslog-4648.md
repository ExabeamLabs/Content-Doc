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
    """__li_source_path="({host}[^"]+)"""",
    """({event_code}4648)""",
    """Subject:\s+Security ID:\s+({user_sid}[^\s]+)""",
    """Subject:.+?Account\sName:\s+(?:-|({user}.+?))\s+Account\sDomain:\s+(?:-|({domain}[^\s]+))\s+Logon\sID:\s+({logon_id}[^\s]+)\s+""",
    """Used:\s+Account\sName:\s+({account}[^\s]+)\s+Account\sDomain:\s+({account_domain}[^\s]+)\s+"""
    """Target\sServer\sName:\s+({dest_host}[^\s+]+)""",
    """Process ID:\s+({process_id}\w+)\s+Process Name:""",
    """Process Name:\s+(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))\s+Network Information:""",
    """Network Address:\s+(?:-|({src_ip}[\d\.]+))""",
    """Additional Information:\s+({dest_service}[^\s]+)\s+Process Information:"""
  ]
  DupFields = ["directory->process_directory"]
}
```