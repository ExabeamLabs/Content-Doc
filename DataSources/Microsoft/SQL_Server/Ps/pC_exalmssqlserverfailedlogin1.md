#### Parser Content
```Java
{
Name = exalms-sqlserver-failed-login-1
  Vendor = Microsoft
  Product = SQL Server
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"provider_name":"MSSQLSERVER"""", """Login failed for user""" ]
  Fields = [
    """"@timestamp"\s{0,100}:\s{0,100}"({time}[^"]{1,2000})"""",
    """"computer_name"\s{0,100}:\s{0,100}"({host}[\w.-]{1,2000}?)"""",
    """CLIENT:\s{0,100}({src_ip}[A-Fa-f\d.:]{1,2000})""",
    """({app}MSSQLSERVER)""",
    """"outcome":"({outcome}[^"]{1,2000})"""",
    """Reason:\s{0,100}({failure_reason}[^"\.\[]{1,2000})""",
    """"message":"({event_name}Login failed for user) '(({domain}[^\\:']{1,2000}?)\\+)?({user}[^:\s']{1,2000})'""",
  ]
  DupFields = [ "host->dest_host" ]


}
```