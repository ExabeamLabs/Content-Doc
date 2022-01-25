#### Parser Content
```Java
{
Name = securesphere-db-failed-login-3
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-failed-login"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """operation="Login"""", """OperationType="""", """databaseName ="""", """|Imperva """, """|SecureSphere|""", """userAuth="False"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """createTime="({time}\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)"""",
    """({event_name}Login failed for user)""",
    """({event_name}logon denied)""",
    """({outcome}failed|denied)""",
    """\WdatabaseName ="(|({database_name}[^"]{1,2000}))"""",
    """\WsrcHost="(|({src_host}[^"]{1,2000}))"""",
    """\WdbUsername="(|(?i)(nt authority\\anonymous logon)|({domain}[^"\\]{1,2000})\\)?(|({db_user}[^"\\]{1,2000}))"""",
    """\WosUser="(|({user}[^"]{1,2000}))"""",
    """\WserviceName ="(|({service_name}[^"]{1,2000}))"""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsrc=(0.0.0.0|({src_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\WappName ="(|({app}[^"]{1,2000}))"""",
    """\WschemaName ="(|({schema}[^"]{1,2000}))"""",
    """errorValue="({reason}[^"]{1,2000})\.?""""
  ]
  DupFields = [ "db_user->account" ]


}
```