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
    """\ssuser=(({domain}[^=\\\/]+)[\\\/]+)?({user}[^\\\/=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """CEF:([^\|]*\|){5}({reason}[^\|]+)""",
    """cs3=({service_name}[^\s]+)"""
    """\sdestinationServiceName=(|({service_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sshost=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\srt=({time}\d{1,100})""",
  ]
}
```