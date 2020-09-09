#### Parser Content
```Java
{
Name = s-oracle-db-query
  Vendor = Oracle
  Lms = Splunk
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """<DB_User>""", """<OS_User>""", """<Userhost>""", """<OS_Process>""", """<DBID>""", """<Sql_Text>""" ]
  Fields = [
  """<Extended_Timestamp>({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d+\w)</Extended_Timestamp>"""
    """<DB_User>(\/|({db_user}.+?))</DB_User>""",
    """<OS_User>({os_user}.+?)</OS_User>""",
    """<Userhost>({src_host}[^\<]+)</Userhost>""",
    """<OS_Process>({process_id}\d+)</OS_Process>""",
    """<Session_Id>({session_id}\d+)</Session_Id>""",
    """<Returncode>({outcome}.+?)</Returncode>""",
    """PROTOCOL=({protocol}[^\)]+)""",
    """PORT=({src_port}.+?)""",
    """<DBID>({database_id}\d+)</DBID>""",
    """<Sql_Text>\s*({db_query}({db_operation}\w+)\s.+?)\s*</Sql_Text>""",
  ]
  DupFields = [ "os_user->user", "db_user->account", "database_id->database_name" ]
 }
```