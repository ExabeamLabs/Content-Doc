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
    """({host}[\w.\-]+)\s{1,100}CEF:([^\|]*\|){4}({event_code}[^\|]+)\|({event_name}[^\|]+)""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """\Wduser=(n/a|(({domain}[^=\\\/]+)[\\\/]+)?({user}[^=\\\/]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wfname=(|({database_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs1=({db_operation}\w+)""",
    """\WdeviceExternalId=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```