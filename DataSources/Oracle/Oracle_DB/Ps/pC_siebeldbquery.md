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
      """<Extended_Timestamp>({time}\d\d\d\d-\d\d-\d\dT\d\d(:\d\d:\d\d.\d{1,100}\w+)?)""",
      """<Userhost>({host}[^<]{1,2000})</Userhost>""",
      """<DB_User>(\/|({db_user}[^<]{1,2000}))</DB_User>""",
      """<OS_User>({user}[^<]{1,2000})</OS_User>""",
      """<DBID>({database_id}\d{1,100})</DBID>""",
      """<Object_Schema>({database_name}[^<]{1,2000})</Object_Schema>""",
      """<Object_Name>({table_name}[^<]{1,2000})</Object_Name>""",
      """<Sql_Text>({db_operation}(?!with|WITH)[^\s]{1,2000})""",
      """<Sql_Text>({db_query}.+?)\s{0,100}</Sql_Text>"""
    ]
    DupFields = [ "db_user->account", "database_id->database_name" ]


}
```