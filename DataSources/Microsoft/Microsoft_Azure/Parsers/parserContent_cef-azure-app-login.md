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
    """\sact=({activity}.+?)\s{1,100}(\w+=|$)""",
    """\srt=({time}\d{1,100})""",
    """\soutcome=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdvc=({host}\S+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wduser=({user_email}[^@\s]+@({email_domain}[^\s@]+))""",
    """\Wsuser=({user_email}[^@\s]+@({email_domain}[^\s@]+))""",
    """\ssuid=(Unknown|({user_email}[^@]+@({email_domain}.+?)))\s{1,100}(\w+=|$)""",
    """CEF:([^\|]*\|){2}({app}[^\|]+)""",
  ]
}
```