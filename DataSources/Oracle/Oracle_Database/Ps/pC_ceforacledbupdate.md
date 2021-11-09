#### Parser Content
```Java
{
Name = cef-oracle-db-update
  Vendor = Oracle
  Product = Oracle Database
  Lms = ArcSight
  DataType = "database-update"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Oracle|FGA|""", """|UPDATE|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wshost=({src_host}[\w\-.]{1,2000})""",
    """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    """\Wsuser=({user}[^\s]{1,2000})""",
    """\Wduser=({db_user}[^\s]{1,2000})""",
    """\Wcs3=({database_name}[^\s]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({db_operation}[^\|]{1,2000})""",
  ]
  DupFields = [ "db_user->account" ]
}
}
```