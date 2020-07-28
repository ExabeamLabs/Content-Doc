#### Parser Content
```Java
{
Name = cef-mssql-database-login
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = ArcSight
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft|SQL Server|""", """categoryBehavior=/Authentication/Verify""" ]
  Fields = [
    """\sduser=(({domain}[^=\\\/]+)[\\\/]+)?({user}[^\\\/=]+?)(\s+\w+=|\s*$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """cs3=({service_name}[^\s]+)"""
    """\sdestinationServiceName=(|({service_name}.+?))(\s+\w+=|\s*$)""",
    """\sshost=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\srt=({time}\d+)""",
    """\scategoryOutcome=/({outcome}.+?)(\s+\w+=|\s*$)""",
  ]
}
```