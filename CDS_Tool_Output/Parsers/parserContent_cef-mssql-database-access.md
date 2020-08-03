#### Parser Content
```Java
{
Name = cef-mssql-database-access
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = ArcSight
  DataType = "database-access"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft|SQL Server|""", """fileType=Security Audit""" ]
  Fields = [
    """\ssuser=(({domain}[^=\\\/]+)[\\\/]+)?({user}[^\\\/=]+?)(\s+\w+=|\s*$)""",
    """CEF:([^\|]*\|){5}({reason}[^\|]+)""",
    """cs3=({service_name}[^\s]+)"""
    """\sdestinationServiceName=(|({service_name}.+?))(\s+\w+=|\s*$)""",
    """\sshost=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\srt=({time}\d+)""",
  ]
}
```