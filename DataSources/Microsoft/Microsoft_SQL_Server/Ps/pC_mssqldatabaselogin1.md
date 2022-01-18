#### Parser Content
```Java
{
Name = mssql-database-login-1
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Splunk
  DataType = "database-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSS"
  Conditions = ["""MSSQLSERVER""", """action_id:LGIF""", """statement:""", """database_principal_name:""", """permission_bitmask:"""]
  Fields = [
    """event_time:({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000})\s\w+""",
    """session_id:({session_id}[^\s]{1,2000})""",
    """\saction_id:({db_operation}[^\s]{1,2000})""",
    """database_name:({database_name}[^\s]{1,2000})""",
    """\sdatabase_principal_name:([^\\]{1,2000}\\)?({db_user}[^\s]{1,2000})\starget_server_principal_name:""",
    """\sserver_principal_name:((NT SERVICE|NT AUTHORITY|NT Service|({domain}[^\\]{1,2000}))?\\)?((?i)system|({user}[^\s]{1,2000}))\sserver_principal_sid:""",
    """Reason:\s({failure_reason}[^\.]{1,2000})""",
    """server_instance_name:({dest_host}[^\s]{1,2000})""",
    """({event_name}LGIF)""",
    """statement:({additional_info}.+?)\sadditional_information:""",
  ]


}
```