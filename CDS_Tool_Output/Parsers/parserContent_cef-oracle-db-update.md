#### Parser Content
```Java
{
Name = cef-oracle-db-update
  Vendor = Oracle
  Lms = ArcSight
  DataType = "database-update"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Oracle|FGA|""", """|UPDATE|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wrt=({time}\d+)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wsuser=({user}[^\s]+)""",
    """\Wduser=({db_user}[^\s]+)""",
    """\Wcs3=({database_name}[^\s]+)""",
    """CEF:([^\|]*\|){5}({db_operation}[^\|]+)""",
  ]
  DupFields = [ "db_user->account" ]
}
```