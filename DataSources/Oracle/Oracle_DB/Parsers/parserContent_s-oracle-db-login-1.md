#### Parser Content
```Java
{
Name = s-oracle-db-login-1
  Vendor = Oracle
  Product = Oracle DB
  Lms = Splunk
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """exabeam_sourcetype=dbx:audit:sql""", """Authenticated by""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """exabeam_sourcetype=dbx:audit:sql:({database_name}[^",\s]+)""",
    """NTIMESTAMP\#="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """USERID="({db_user}[^"]+)""",
    """USERHOST="({src_host}[^"]+)""",
    """RETURNCODE="({outcome}[^"]+)""",
    """Client address.+?\(PROTOCOL=({protocol}[^\)]+)""",
    """Client address.+?\(HOST=({src_ip}[A-Fa-f:\d.]+)""",
    """SPARE1="({os_user}[^"]+)""",
  ]
  DupFields = [ "db_user->account", "os_user->user" ]
}
```