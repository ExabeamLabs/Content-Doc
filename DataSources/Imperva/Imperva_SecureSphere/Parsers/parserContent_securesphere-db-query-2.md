#### Parser Content
```Java
{
Name = securesphere-db-query-2
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Imperva |""", """rawdata=""", """eventtype=Query""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\ssrc=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sspt=({src_port}\d+)""",
    """\sdst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sdpt=({dest_port}\d+)""",
    """\sprotocol=({protocol}.*?)\s\w+=""",
    """\sservicename=({service_name}.*?)\s\w+=""",
    """\sappname=({app}.*?)\s\w+=""",
    """\seventtype=({log_type}.*?)\s\w+=""",
    """\soperationname=({db_operation}.*?)\s\w+=""",
    """\ssrchostname=({src_host}[^\s]+)""",
    """\sdbname=({db_name}[^\s]+)""",
    """\sschemaname=({db_schema}[^\s]+)"""
    """\sresponsesize=({response_size}.*?)\s\w+=""",
    """\sosuser=({os_user}[^\s]+)""",
    """\sduser=({db_user}[^\s]+)""", 
    """\sobjectname=({object_name}[^\s]+)""",
    """\srawdata=#\(({db_query}[^\)]+)""",
  ]
  DupFields = [ "db_user->account", "os_user->user" ]
}
```