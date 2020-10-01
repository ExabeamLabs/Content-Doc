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
      """"date":"({time}\d+)""",
      """"user":"({db_user}[^"]+)""",
      """"ip":"({dest_ip}[a-fA-F\d.:]+)""",
      """"host":"({dest_host}[^"]+)""",
      """"_os":"({os}[^"]+)""",
      """"_client_name":"({app}[^"]+)""",
      """"rows":"({response_size}[^"]+)""",
      """"pid":"({pid}[^"]+)""",
      """"os_user":"({user}[^"]+)""",
      """"status":"({outcome}[^"]+)""",
      """"cmd":"({db_operation}[^"]+)""",
      """"db":"({database_name}[^"]+)""",
      """"name":"({database_object}[^"]+)""",
      """"query":"({db_query}[^"]+)""",
    ]
    DupFields = [ "dest_host->host" ]
  }
```