#### Parser Content
```Java
{
Name = siebel-db-query
    Vendor = Oracle
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
```