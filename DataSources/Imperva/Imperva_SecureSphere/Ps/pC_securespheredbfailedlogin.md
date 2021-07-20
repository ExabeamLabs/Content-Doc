#### Parser Content
```Java
{
Name = securesphere-db-failed-login
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-failed-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Imperva |""", """operationname=Login""", """authenticated=False""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\ssrc=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sspt=({src_port}\d{1,100})""",
    """\sdst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sdpt=({dest_port}\d{1,100})""",
    """\sprotocol=({protocol}.*?)\s\w+=""",
    """\sservicename=({service_name}.*?)\s\w+=""",
    """\sservergroup=({server_group}[^\s]{1,2000})""",
    """\sappname=({app}.*?)\s\w+=""",
    """\sauthenticated=({outcome}\s\w+=)""",
    """\ssrchostname=({src_host}[^\s]{1,2000})""",
    """\sdbname=({db_name}[^\s]{1,2000})""",
    """\sschemaname=({db_schema}[^\s]{1,2000})""",
    """\sresponsesize=({response_size}.*?)\s\w+=""",
    """\sosuser=({os_user}[^\s]{1,2000}])""",
    """\sduser=({db_user}[^\s]{1,2000})""", 
  ]
  DupFields = [ "db_user->account", "os_user->user" ]
}
```