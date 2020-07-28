#### Parser Content
```Java
{
Name = sysmon-windows-dns-query
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """QueryName:""", """QueryResults:""", """ProcessGuid:""", """Image:""" ]
  Fields = [
    """UtcTime:\s*({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d\.\d\d\d)\s""",
    """exabeam_host=({host}[\w.\-]+)""",
    """QueryName:\s*({query}[^\s]+)""",
    """ProcessGuid:\s*\{({process_guid}[A-F0-9a-f-]+)\}""",
    """ProcessId:\s*({pid}\d+)""",
    """QueryResults:\s({response}.+?)\sImage:""",
    """Image:\s*(?:<unknown process>|({process}({directory}[^"]*[\\\/]+)?({process_name}[^"\\\/]+)))\s""",
	]
}

{
  Name = mssql-database-query-2
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Splunk
  DataType = "database-query"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSS"
  Conditions = [ """server_instance_name""", """exa_jdbc_type""", """SQL Server""", """database_name""" ]
  Fields = [
    """exabeam_host=([^=@]+@\s*)?({host}\S+)""", 
    """"+event_time"+:"+({time}[^"]+)""",
    """"+server_principal_name"+:"+(({domain}[^\\"]+?)\\+({user}[^"]+)|({db_user}[^"]+))""",
    """"+server_instance_name"+:"+({dest_host}[^"]+)""",
    """"+statement"+:"+({db_query}.+?)\s*"+""",
    """"+server_principal_sid"+:"+\s*({db_user_sid}.+?)\s*"+""",
    """"+action_id"+:"+({db_operation}.+?)\s*"+"""
    """"+database_name"+:"+({database_name}[^"]+)"+,""",
    """"+schema_name"+:"+({schema_name}[^"]+)"+,""",
    """"+object_name"+:"+({table_name}[^"]+)"+,""",
    """"+succeeded"+:"?({outcome}[^\s,]+)""",
    ]
}

{
  Name = sysmon-file-delete
  Vendor = Microsoft
  Product = Sysmon
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """File Delete:""", """IMPHASH=""", """User:""" ]
  Fields = [
    """exabeam_host=([^=@]+@\s*)?({host}\S+)""",
    """({event_name}File Delete)""",
    """\s({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)\s""",
    """ProcessGuid:\s\{({process_guid}[^\}]+)\}""",
    """ProcessId:\s({pid}\d+)""",
    """User:\s(NT|[^\\]+\\({user}[^\s]+))""",
    """Image:\s+({process}({directory}[^"]*?[\\\/]+)?({process_name}[^\s]+))\s+\w+:""",
    """TargetFilename:\s({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))\s\w+:""",
    """MD5=({md5}[^,]+),""",
    """SHA256=({sha256}[^,]+),""",
  ]
}
```