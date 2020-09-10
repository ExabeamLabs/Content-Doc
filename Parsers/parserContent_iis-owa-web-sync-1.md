#### Parser Content
```Java
{
Name = iis-owa-web-sync-1
    Vendor = Microsoft
    Product = Microsoft Owa 
    Lms = Direct
    DataType = "web-activity"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """<custom conditions>"""]
    Fields = [
      """({time}\d+-\d+-\d+\s\d+:\d+:\d+)\s*({src_host}[^\s]+)?\s+\s*({method}[^\s]+)\s*({uri_path}[^\s]+)\s*[^\s]+\s+({dest_port}\d+)\s*-\s*({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s*({user_agent}[^\s]+)\s*(-|(https:\/\/|:http\/\/)({web_domain}.+?\.({top_domain}\w+\.\w+)))(\/|\/[^\s]+)?\s*({result_code}\d+)\s*\d+\s*\d+\s*\d*\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s*"""
    ]
}

{  
  Name = "microsoft-graph-security-alert"
  Vendor = "Microsoft"
  Product = "Microsoft Graph"
  Lms = "Splunk"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  DataType = "security-alert"
  Conditions = [ """microsoft_graph_security""", """GraphSecurityAlert""", """"eventDateTime"""", """"title"""", """":""" ]
  Fields=[
    """"eventDateTime"+:\s*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"description"+:\s*"+({additional_info}[^"]+)"""",
    """"id"+:\s*"+({alert_id}[^"]+)"""",
    """"title"+:\s*"+({alert_name}[^"]+)"""",
    """"severity"+:\s*"+({alert_severity}[^"]+)"""",
    """"category"+:\s*"+({alert_type}[^"]+)"""",
    """"domainName"+:\s*"+({domain}[^"]+)"""",
    """"logonLocation"+:\s*"+({location}[^"]+)"""",
    """"logonIp"+:\s*"+({src_ip}[^"]+)"""",
    """"accountName"+:\s*"+({user}[^"#]+)""",
    """"aadUserId"+:\s*"+({user_sid}[^"]+)""""
    ""","({host}[^"]+?)","\{"""",
  ]
}

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