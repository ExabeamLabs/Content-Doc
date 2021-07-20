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
    """({host}[\w.\-]{1,2000})\s{1,100}CEF:([^\|]{0,2000}\|){4}({event_code}[^\|]{1,2000})\|({event_name}[^\|]{1,2000})""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """\Wduser=(n/a|(({domain}[^=\\\/]{1,2000})[\\\/]{1,2000})?({user}[^=\\\/]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wfname=(|({database_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs1=({db_operation}\w+)""",
    """\WdeviceExternalId=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```