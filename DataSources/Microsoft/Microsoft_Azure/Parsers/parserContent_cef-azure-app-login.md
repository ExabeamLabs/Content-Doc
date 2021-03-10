#### Parser Content
```Java
{
Name = cef-azure-app-login
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Azure""", """UserLoggedIn""", """ suid=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\sact=({activity}.+?)\s+(\w+=|$)""",
    """\srt=({time}\d+)""",
    """\soutcome=({outcome}.+?)\s+(\w+=|$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdvc=({host}\S+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wduser=({user_email}[^@\s]+@[^\s@]+)""",
    """\Wsuser=({user_email}[^@\s]+@[^\s@]+)""",
    """\ssuid=(Unknown|({user_email}.+?))\s+(\w+=|$)""",
    """CEF:([^\|]*\|){2}({app}[^\|]+)""",
  ]
}
```