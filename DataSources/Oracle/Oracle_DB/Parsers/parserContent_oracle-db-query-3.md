#### Parser Content
```Java
{
Name = oracle-db-query-3
  Vendor = Oracle
  Product = Oracle DB
  Lms = Direct
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"OracleFGA"""", """"sqlText":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"objName":"({database_object}[^"]+)""",
    """"sqlText":"({db_query}.*?)","""",
    """"objSchema":"({schema}[^"]+)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"srcHostname":"(({domain}[^"\\\/]+)[\\\/]+)?({src_host}[^"]+)""",
    """"action":"({db_operation}[^"]+)""",
    """"instanceName":"({database_name}[^"]+)""",
    """"suUserID":"({os_user}[^"]+)""",
    """"userID":"({db_user}[^"]+)""",
  ]
  DupFields = [ "os_user->user" ]
}
```