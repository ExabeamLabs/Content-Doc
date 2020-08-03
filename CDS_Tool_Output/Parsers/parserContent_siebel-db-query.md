#### Parser Content
```Java
{
Name = siebel-db-query
    Vendor = Oracle
  Product = Oracle DB
    Lms = Direct
    DataType = "database-query"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
    Conditions = [ """<Sql_Text>""","""<DB_User>""" ]
    Fields = [ 
      """<Extended_Timestamp>({time}\d\d\d\d-\d\d-\d\dT\d\d(:\d\d:\d\d.\d+\w+)?)""",
      """<Userhost>({host}[^<]+)</Userhost>""",
      """<DB_User>(\/|({db_user}[^<]+))</DB_User>""",
      """<OS_User>({user}[^<]+)</OS_User>""",
      """<DBID>({database_id}\d+)</DBID>""",
      """<Object_Schema>({database_name}[^<]+)</Object_Schema>""",
      """<Object_Name>({table_name}[^<]+)</Object_Name>""",
      """<Sql_Text>({db_operation}(?!with|WITH)[^\s]+)""",
      """<Sql_Text>({db_query}.+?)\s*</Sql_Text>"""
    ]
    DupFields = [ "db_user->account", "database_id->database_name" ]
}

{
  Name = oracle-db-access
  Vendor = Oracle
  Product = Oracle
  Lms = Direct
  DataType = "database-access"
  IsHVF = true
  TimeFormat = "dd-MM-yyyy HH:mm:ss"
  Conditions = [ """CONNECT_DATA=""", """SERVICE_NAME=""", """INSTANCE_NAME=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """({time}\d+-\w+-\d+\s+\d\d:\d\d:\d\d)\s""",
    """PORT=({dest_port}\d+)""",
    """HOST=({dest_host}[\w\-.]+)\)\(USER=""",
    """HOST=({dest_ip}[A-Fa-f:\d.]+)\)\(PORT=""",
    """PROGRAM=({process_name}[^\)]+)""",
    """PROTOCOL=({protocol}[^\)]+)""",
    """SERVICE_NAME=({app}[^\)]+)""",
    """USER=({user}[^\)\s]+)""",
    """\(PORT=\d+\)\)\s*\*\s*({outcome}[^\s\*]+)""",
  ]
}
```