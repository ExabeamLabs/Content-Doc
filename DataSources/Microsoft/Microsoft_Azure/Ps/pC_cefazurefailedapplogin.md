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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\sact=({activity}.+?)\s{1,100}(\w+=|$)""",
    """\srt=({time}\d{1,100})""",
    """\soutcome=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=({host}[\w\-.]{1,2000})""",
    """\sduser=({user_email}[^@\s]{1,2000}@[^\s@]{1,2000})""",
    """\ssuser=({user_email}[^@\s]{1,2000}@[^\s@]{1,2000})""",
    """\ssuid=({user_email}.+?)\s{1,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){2}({app}[^\|]{1,2000})""",
  ]


}
```