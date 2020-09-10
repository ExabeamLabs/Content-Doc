#### Parser Content
```Java
{
Name = mssql-database-query-3
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Splunk
  DataType = "database-query"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """HostName=""", """DatabaseName=""", """SessionLoginName=""", """EventClass=""", """, TextData=""" ]
  Fields = [
    """HostName="+({host}[^"]+)""",
    """StartTime="+({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d+)""",
    """DatabaseName="+({database_name}[^"]+)""",
    """SessionLoginName="+(({domain}[^\\"]+?)\\+({user}[^"]+)|({db_user}[^"]+))""",
    """NTDomainName="+({domain}[^"]+)""",
    """TextData="+({db_query}.+?)\s*"""",
    """EventClass="+({event_code}\d+)""",
    """TextData.+?({db_operation}UPDATE|REMOVE|INSERT|ADD_USER|DELETE)""",
    """ApplicationName="+({app}[^"]+)"""
	]
}
```