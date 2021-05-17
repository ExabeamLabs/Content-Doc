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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\sact=({activity}.+?)\s{1,100}(\w+=|$)""",
    """\srt=({time}\d{1,100})""",
    """\soutcome=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdvc=({host}\S+)""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wduser=({user_email}[^@\s]{1,2000}@({email_domain}[^\s@]{1,2000}))""",
    """\Wsuser=({user_email}[^@\s]{1,2000}@({email_domain}[^\s@]{1,2000}))""",
    """\ssuid=(Unknown|({user_email}[^@]{1,2000}@({email_domain}.+?)))\s{1,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){2}({app}[^\|]{1,2000})""",
  ]
}
```