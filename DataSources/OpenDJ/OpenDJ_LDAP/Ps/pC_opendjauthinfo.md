#### Parser Content
```Java
{
Name = opendj-auth-info
  Vendor = OpenDJ
  Product = OpenDJ LDAP
  Lms = Splunk
  DataType = "authentication-attempt"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
  Conditions = [ """from=""", """to=""", """] CONNECT conn=""", """protocol=LDAP""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\[({time}\d\d\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [-\+]\d{1,100})\]""",
    """conn=({conn_id}\d{1,100})""",
    """from=({src_ip}[A-Fa-f:\d.]{1,2000})(:({src_port}\d{1,100}))""",
    """to=({dest_ip}[A-Fa-f:\d.]{1,2000})(:({dest_port}\d{1,100}))""",
    """protocol=({auth_method}[^\s]{1,2000})"""
  ]
}
```