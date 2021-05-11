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
    """\sact=({activity}.+?)\s{1,100}(\w+=|$)""",
    """\srt=({time}\d{1,100})""",
    """\soutcome=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=({host}[\w\-.]+)""",
    """\sduser=({user_email}[^@\s]+@[^\s@]+)""",
    """\ssuser=({user_email}[^@\s]+@[^\s@]+)""",
    """\ssuid=({user_email}.+?)\s{1,100}(\w+=|$)""",
    """CEF:([^\|]*\|){2}({app}[^\|]+)""",
  ]
}
```