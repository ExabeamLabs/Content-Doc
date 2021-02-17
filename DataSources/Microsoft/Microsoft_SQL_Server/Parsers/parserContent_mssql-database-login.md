#### Parser Content
```Java
{
Name = mssql-database-login
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Splunk
  DataType = "database-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """HostName=""", """DatabaseName=""", """SessionLoginName=""", """EventClass="14"""" ]
  Fields = [
    """HostName="+({host}[^"]+)""",
    """StartTime="+({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d+)""",
    """DatabaseName="+({database_name}[^"]+)""",
    """SessionLoginName="+(({domain}[^\\"]+?)\\+({user}[^"]+)|({db_user}[^"]+))""",
    """NTDomainName="+({domain}[^"]+)""",
    """TextData="+({db_query}.+?)\s*"""",
    """EventClass="+({event_code}\d+)""",
    """ApplicationName="+({app}[^"]+)"""
	]
}
```