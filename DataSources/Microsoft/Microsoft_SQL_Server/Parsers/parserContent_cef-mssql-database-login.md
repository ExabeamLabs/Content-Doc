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
    """\sduser=(({domain}[^=\\\/]{1,2000})[\\\/]{1,2000})?({user}[^\\\/=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """cs3=({service_name}[^\s]{1,2000})"""
    """\sdestinationServiceName=(|({service_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sshost=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\srt=({time}\d{1,100})""",
    """\scategoryOutcome=/({outcome}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```