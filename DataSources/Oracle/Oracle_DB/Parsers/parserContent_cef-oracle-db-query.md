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
    """exabeam_host=([^=]*@\s{0,100})?({host}[^\s]+)""",
    """\|Oracle\|FGA\|([^\|]*\|){2}({db_operation}[^\|]+)""",
    """\WeventId=({event_code}\d{1,100})""",
    """\Wmsg=\s{0,100}({db_query}([^\\=]|(\\\\)*\\=|\\)+)\s{1,100}(\w+=|$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wshost=({src_host}[^\s]+)""",
    """\Wsuser=({user}[^\s]+)""",
    """\Wdhost=({dest_host}[^\s]+)""",
    """\Wduser=({db_user}[^\s]+)""",
    """\Wcs3=({database_name}[^\s]+)"""
  ]
  DupFields = ["db_user->account"]
}
```