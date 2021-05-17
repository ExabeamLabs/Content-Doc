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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\d\d:\d\d:\d\d\s({src_ip}[\dA-Fa-f.:]{1,2000})""",
    """({event_name}Successful login)""",
    """Successful login on\s{0,100}\[?({dest_ip}[a-fA-F\d.:]{1,2000})\]?""",
    """Username:\s{0,100}"{1,20}({user}[^"]{1,2000})""",
    """({auth_package}SSH)"""
  ]
}
```