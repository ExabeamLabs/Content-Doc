#### Parser Content
```Java
{
Name = cef-microsoft-database-delete
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = ArcSight
  DataType = "database-delete"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Conditions = [ """CEF:""", """|LOGbinder|SQL|""", """|24087|Issued a delete database command""" ]
  Fields = [
    """({host}[\w.\-]+)\s+CEF:([^\|]*\|){4}({event_code}[^\|]+)\|({event_name}[^\|]+)""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """\Wduser=(n/a|(({domain}[^=\\\/]+)[\\\/]+)?({user}[^=\\\/]+?))(\s+\w+=|\s*$)""",
    """\Wfname=(|({database_name}.+?))(\s+\w+=|\s*$)""",
    """\Wcs1=({db_operation}\w+)""",
    """\WdeviceExternalId=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
  ]
}
```