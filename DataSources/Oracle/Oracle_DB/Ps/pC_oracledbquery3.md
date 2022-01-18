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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"objName":"({database_object}[^"]{1,2000})""",
    """"sqlText":"({db_query}.*?)","""",
    """"objSchema":"({schema}[^"]{1,2000})""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"srcHostname":"(({domain}[^"\\\/]{1,2000})[\\\/]{1,2000})?({src_host}[^"]{1,2000})""",
    """"action":"({db_operation}[^"]{1,2000})""",
    """"instanceName":"({database_name}[^"]{1,2000})""",
    """"suUserID":"({os_user}[^"]{1,2000})""",
    """"userID":"({db_user}[^"]{1,2000})""",
  ]
  DupFields = [ "os_user->user" ]


}
```