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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\srawuser=({db_user}[^\s]{1,2000})""",
    """\sservicename=({service_name}[^\s]{1,2000})""",
    """\sservergroup=({server_group}[^\s]{1,2000})""",
    """\salerttype=({alert_type}[^\s]{1,2000})""",
    """\sseverity=({alert_severity}[^\s]{1,2000})""",
    """\sact=(None|({action}[^\s]{1,2000}))""",
    """\ssrc=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sspt=({src_port}\d{1,100})""",
    """\sdst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sdpt=({dest_port}\d{1,100})""",
    """\ssrchostname=({src_host}[^\s]{1,2000})""",
    """\sdbname=({db_name}[^\s]{1,2000})""",
    """\sschemaname=({schema}[^\s]{1,2000})""",
    """\sresponsesize=({response_size}[^\s]{1,2000})""",
    """\salertdesc=#\(({alert_name}[^\)]{1,2000})""",
    """\srawdata=#\(({db_query}[^\)]{1,2000})""",

  ]
  DupFields = [ "db_user->account"]
}
```