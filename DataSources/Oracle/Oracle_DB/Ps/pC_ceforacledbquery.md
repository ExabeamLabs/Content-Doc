#### Parser Content
```Java
{
Name = cef-oracle-db-query
  Vendor = Oracle
  Product = Oracle DB
  Lms = ArcSight
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Oracle|FGA|""", """|SELECT|""" ]
  Fields = [ 
    """exabeam_host=([^=]{0,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\|Oracle\|FGA\|([^\|]{0,2000}\|){2}({db_operation}[^\|]{1,2000})""",
    """\WeventId=({event_code}\d{1,100})""",
    """\Wmsg=\s{0,100}({db_query}([^\\=]|(\\\\)*\\=|\\)+)\s{1,100}(\w+=|$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wshost=({src_host}[^\s]{1,2000})""",
    """\Wsuser=({user}[^\s]{1,2000})""",
    """\Wdhost=({dest_host}[^\s]{1,2000})""",
    """\Wduser=({db_user}[^\s]{1,2000})""",
    """\Wcs3=({database_name}[^\s]{1,2000})"""
  ]
  DupFields = ["db_user->account"]


}
```