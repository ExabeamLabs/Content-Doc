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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_sourcetype=dbx:audit:sql:({database_name}[^",\s]{1,2000})""",
    """NTIMESTAMP\#="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """USERID="({db_user}[^"]{1,2000})""",
    """USERHOST="({src_host}[^"]{1,2000})""",
    """RETURNCODE="({outcome}[^"]{1,2000})""",
    """Client address.+?\(PROTOCOL=({protocol}[^\)]{1,2000})""",
    """Client address.+?\(HOST=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """SPARE1="({os_user}[^"]{1,2000})""",
  ]
  DupFields = [ "db_user->account", "os_user->user" ]
}
```