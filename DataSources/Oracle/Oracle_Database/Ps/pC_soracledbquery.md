#### Parser Content
```Java
{
Name = s-oracle-db-query
  Vendor = Oracle
  Product = Oracle Database
  Lms = Splunk
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """<DB_User>""", """<OS_User>""", """<Userhost>""", """<OS_Process>""", """<DBID>""", """<Sql_Text>""" ]
  Fields = [
  """<Extended_Timestamp>({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,100}\w)</Extended_Timestamp>"""
    """<DB_User>(\/|({db_user}.+?))</DB_User>""",
    """<OS_User>({os_user}.+?)</OS_User>""",
    """<Userhost>({src_host}[^\<]{1,2000})</Userhost>""",
    """<OS_Process>({process_id}\d{1,100})</OS_Process>""",
    """<Session_Id>({session_id}\d{1,100})</Session_Id>""",
    """<Returncode>({outcome}.+?)</Returncode>""",
    """PROTOCOL=({protocol}[^\)]{1,2000})""",
    """PORT=({src_port}.+?)""",
    """<DBID>({database_id}\d{1,100})</DBID>""",
    """<Sql_Text>\s{0,100}({db_query}({db_operation}\w+)\s.+?)\s{0,100}</Sql_Text>""",
  ]
  DupFields = [ "os_user->user", "db_user->account", "database_id->database_name" ]
 

}
```