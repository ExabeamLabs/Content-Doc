#### Parser Content
```Java
{
Name = securesphere-db-alert-2
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Imperva |""", """violateditem=""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\srawuser=({db_user}[^\s]+)""",
    """\sservicename=({service_name}[^\s]+)""",
    """\sservergroup=({server_group}[^\s]+)""",
    """\salerttype=({alert_type}[^\s]+)""",
    """\sseverity=({alert_severity}[^\s]+)""",
    """\sact=(None|({action}[^\s]+))""",
    """\ssrc=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sspt=({src_port}\d+)""",
    """\sdst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sdpt=({dest_port}\d+)""",
    """\ssrchostname=({src_host}[^\s]+)""",
    """\sdbname=({db_name}[^\s]+)""",
    """\sschemaname=({schema}[^\s]+)""",
    """\sresponsesize=({response_size}[^\s]+)""",
    """\salertdesc=#\(({alert_name}[^\)]+)""",
    """\srawdata=#\(({db_query}[^\)]+)""",

  ]
  DupFields = [ "db_user->account"]
}
```