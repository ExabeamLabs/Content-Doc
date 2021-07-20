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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\ssrc=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sspt=({src_port}\d{1,100})""",
    """\sdst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sdpt=({dest_port}\d{1,100})""",
    """\sprotocol=({protocol}.*?)\s\w+=""",
    """\sservicename=({service_name}.*?)\s\w+=""",
    """\sappname=({app}.*?)\s\w+=""",
    """\seventtype=({log_type}.*?)\s\w+=""",
    """\soperationname=({db_operation}.*?)\s\w+=""",
    """\ssrchostname=({src_host}[^\s]{1,2000})""",
    """\sdbname=({db_name}[^\s]{1,2000})""",
    """\sschemaname=({db_schema}[^\s]{1,2000})"""
    """\sresponsesize=({response_size}.*?)\s\w+=""",
    """\sosuser=({os_user}[^\s]{1,2000})""",
    """\sduser=({db_user}[^\s]{1,2000})""", 
    """\sobjectname=({object_name}[^\s]{1,2000})""",
    """\srawdata=#\(({db_query}[^\)]{1,2000})""",
  ]
  DupFields = [ "db_user->account", "os_user->user" ]
}
```