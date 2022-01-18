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
    """"@timestamp"\s{0,100}:\s{0,100}"({time}[^"]{1,2000})"""",
    """"computer_name"\s{0,100}:\s{0,100}"({host}.+?)"""",
    """"source_name":"({app}[^"]{1,2000})"""",
    """"(param1|user)"\s{0,100}:\s{0,100}"({user}[^"]{1,2000})"""",
    """"message":".*?({failure_reason}because[^.]{1,2000})\.""",
  ]
  DupFields = [ "host->dest_host" ]


}
```