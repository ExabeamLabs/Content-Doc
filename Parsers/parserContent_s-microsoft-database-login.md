#### Parser Content
```Java
{
Name = s-microsoft-database-login
  Vendor = Microsoft
  Product = SQL Server
  Lms = Splunk
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [""", instance_name=""",""", account_name=""",""", client_name=""",""", application_name="""]
  Fields = [
      """\sinstance_name="({additional_info}[^"]+)""",
      """\saccount_name="(({domain}[^\\\/"]+?)[\\\/]+)?({user}[^\\\/"]+?)\s*"""",
      """\sclient_name="({src_host}[^"]+)""",
      """\sapplication_name="({app}[^"]+)""",
      """\sdatabase_name="({database_name}[^"]+)""",
      """\serr_desc="({outcome}[^"]+)""",
      """\sfirst_login="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)""",
      """exabeam_host=({host}[\w.\-]+)""",
    ]
}

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