#### Parser Content
```Java
{
Name = cef-azure-failed-app-login
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = ArcSight
  DataType = "failed-app-login"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Azure""", """UserLoginFailed""", """ suid=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\sact=({activity}.+?)\s+(\w+=|$)""",
    """\srt=({time}\d+)""",
    """\soutcome=({outcome}.+?)\s+(\w+=|$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=({host}[\w\-.]+)""",
    """\sduser=({user_email}[^@\s]+@[^\s@]+)""",
    """\ssuser=({user_email}[^@\s]+@[^\s@]+)""",
    """\ssuid=({user_email}.+?)\s+(\w+=|$)""",
    """CEF:([^\|]*\|){2}({app}[^\|]+)""",
  ]
}
```