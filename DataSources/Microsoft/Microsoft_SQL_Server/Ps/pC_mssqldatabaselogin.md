#### Parser Content
```Java
{
Name = mssql-database-login
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Splunk
  DataType = "database-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """HostName =""", """DatabaseName =""", """SessionLoginName =""", """EventClass="14"""" ]
  Fields = [
    """HostName ="{1,20}({host}[^"]{1,2000})""",
    """StartTime="{1,20}({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d{1,100})""",
    """DatabaseName ="{1,20}({database_name}[^"]{1,2000})""",
    """SessionLoginName ="{1,20}(({domain}[^\\"]{1,2000}?)\\+({user}[^"]{1,2000})|({db_user}[^"]{1,2000}))""",
    """NTDomainName ="{1,20}({domain}[^"]{1,2000})""",
    """TextData="{1,20}({db_query}.+?)\s{0,100}"""",
    """EventClass="{1,20}({event_code}\d{1,100})""",
    """ApplicationName ="{1,20}({app}[^"]{1,2000})"""
	]


}
```