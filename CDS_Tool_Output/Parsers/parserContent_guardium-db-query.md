#### Parser Content
```Java
{
Name = guardium-db-query
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Direct
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """SQLID=""", """AppUserName=""", """DB_NAME=""", """DBUser=""" ]
  Fields = [
    """({host}[\w.\-]+)\s+\w+\[.*?\]:\s*AppUserName=""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\WreceiptTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\WAppUserName=PLAN=({os_user}[^;\|]+?)\s*(?:;|\||$)""",
    """\WPROG=({source_program}[^;\|]+?)\s*(?:;|\||$)""",
    """\WDB_NAME=({database_name}[^;\|]+?)\s*(?:;|\||$)""",
    """\WclientHostname=({src_host}[^;\|]+?)\s*(?:;|\||$)""",
    """\WclientIP=({src_ip}[a-fA-F\d.:]+)""",
    """\WclientPort=({src_port}\d+)""",
    """\WDBProtocol=({db_protocol}[^;\|]+?)\s*(?:;|\||$)""",
    """\WDBUser=({db_user}[^;\|]+?)\s*(?:;|\||$)""",
    """\WruleDescription=({rule_description}[^;\|]+?)\s*(?:;|\||$)""",
    """\WserverType=({server_group}[^;\|]+?)\s*(?:;|\||$)""",
    """\WserviceName=({service_name}[^;\|]+?)\s*(?:;|\||$)""",
    """\WVerb=({db_operation}[^;\|]+?)\s*(?:;|\||$)""",
  ]
  DupFields = [ "db_user->account", "os_user->user" ]
}
```