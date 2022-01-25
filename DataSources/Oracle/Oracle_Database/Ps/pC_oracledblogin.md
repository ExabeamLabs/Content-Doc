#### Parser Content
```Java
{
Name = oracle-db-login
  Vendor = Oracle
  Product = Oracle Database
  Lms = Direct
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"os_username""", """"dbid""", """"LOGON""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"dbid\\?"{1,20}:\\?"{1,20}({database_id}[^"\\]{1,2000})""",
    """HOST=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"userhost\\?"{1,20}:\\?"{1,20}({src_host}[^"\\]{1,2000})""",
    """"userhost"{1,20}:"{1,20}({domain}[^"\\]{1,2000})\\{1,2}({src_host}[^"\\]{1,2000})"""",
    """"terminal\\?"{1,20}:\\?"{1,20}({terminal}[^"\\]{1,2000})""",
    """"timestamp\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"username\\?"{1,20}:\\?"{1,20}({db_user}[^"\\]{1,2000})""",
    """"os_username\\?"{1,20}:\\?"{1,20}({os_user}[^"\\]{1,2000})""",
    """PROTOCOL=({protocol}\w+)""",
    """"returncode\\?"{1,20}:\\?"{1,20}({return_code}[^"\\]{1,2000})""",
    """"exa_jdbc_database":"({database_name}[^"]{1,2000})"""",
    """"exa_jdbc_type":"({app}[^"]{1,2000})"""",
    """"exa_jdbc_hostname":"({dest_host}[^"]{1,2000})"""",
    """"exa_jdbc_port":"({dest_port}\d{1,100})""""
  ]
  DupFields = [ "os_user->user", "db_user->account" ]


}
```