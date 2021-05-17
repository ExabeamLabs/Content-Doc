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
    """({host}[\w.\-]{1,2000})\s{1,100}\w+\[.*?\]:\s{0,100}AppUserName=""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\WreceiptTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\WAppUserName=PLAN=({os_user}[^;\|]{1,2000}?)\s{0,100}(?:;|\||$)""",
    """\WPROG=({source_program}[^;\|]{1,2000}?)\s{0,100}(?:;|\||$)""",
    """\WDB_NAME=({database_name}[^;\|]{1,2000}?)\s{0,100}(?:;|\||$)""",
    """\WclientHostname=({src_host}[^;\|]{1,2000}?)\s{0,100}(?:;|\||$)""",
    """\WclientIP=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\WclientPort=({src_port}\d{1,100})""",
    """\WDBProtocol=({db_protocol}[^;\|]{1,2000}?)\s{0,100}(?:;|\||$)""",
    """\WDBUser=({db_user}[^;\|]{1,2000}?)\s{0,100}(?:;|\||$)""",
    """\WruleDescription=({rule_description}[^;\|]{1,2000}?)\s{0,100}(?:;|\||$)""",
    """\WserverType=({server_group}[^;\|]{1,2000}?)\s{0,100}(?:;|\||$)""",
    """\WserviceName=({service_name}[^;\|]{1,2000}?)\s{0,100}(?:;|\||$)""",
    """\WVerb=({db_operation}[^;\|]{1,2000}?)\s{0,100}(?:;|\||$)""",
  ]
  DupFields = [ "db_user->account", "os_user->user" ]
}
```