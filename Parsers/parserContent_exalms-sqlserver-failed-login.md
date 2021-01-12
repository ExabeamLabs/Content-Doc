#### Parser Content
```Java
{
Name = exalms-sqlserver-failed-login
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"source_name":"MSSQLSERVER"""", """Login failed for user""" ]
  Fields = [
    """"@timestamp"\s*:\s*"({time}[^"]+)"""",
    """"computer_name"\s*:\s*"({host}.+?)"""",
    """"source_name":"({app}[^"]+)"""",
    """"(param1|user)"\s*:\s*"({user}[^"]+)"""",
    """"message":".*?({failure_reason}because[^.]+)\.""",
  ]
  DupFields = [ "host->dest_host" ]
}
```