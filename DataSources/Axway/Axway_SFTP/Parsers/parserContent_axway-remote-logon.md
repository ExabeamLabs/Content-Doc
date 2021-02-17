#### Parser Content
```Java
{
Name = axway-remote-logon
  Vendor = Axway
  Product = Axway SFTP
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """user:INFO""", """SSH: Successful login on""", """Username:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\d\d:\d\d:\d\d\s({src_ip}[\dA-Fa-f.:]+)""",
    """({event_name}Successful login)""",
    """Successful login on\s*\[?({dest_ip}[a-fA-F\d.:]+)\]?""",
    """Username:\s*"+({user}[^"]+)""",
    """({auth_package}SSH)"""
  ]
}
```