#### Parser Content
```Java
{
Name = mysql-db-activity-json
    Vendor = Mysql
  Product = Mysql
    Lms = Direct
    DataType = "database-operation"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """"msg-type":"activity"""", """"query":""" ]
    Fields = [
      """"date":"({time}\d{1,100})""",
      """"user":"({db_user}[^"]{1,2000})""",
      """"ip":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """"host":"({dest_host}[^"]{1,2000})""",
      """"_os":"({os}[^"]{1,2000})""",
      """"_client_name":"({app}[^"]{1,2000})""",
      """"rows":"({response_size}[^"]{1,2000})""",
      """"pid":"({pid}[^"]{1,2000})""",
      """"os_user":"({user}[^"]{1,2000})""",
      """"status":"({outcome}[^"]{1,2000})""",
      """"cmd":"({db_operation}[^"]{1,2000})""",
      """"db":"({database_name}[^"]{1,2000})""",
      """"name":"({database_object}[^"]{1,2000})""",
      """"query":"({db_query}[^"]{1,2000})""",
    ]
    DupFields = [ "dest_host->host" ]
  }
```