#### Parser Content
```Java
{
Name = cef-exchange-app-activity-7
  Conditions = [ """CEF:""", """|Exchange Online|""", """|New-Mailbox|""" ]
}
cef-exchange-app-activity-1 = {
  Vendor = Microsoft
  Product = Exchange
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """\Wdvc=({host}\S+)""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wact=({activity}.+?)\s{1,100}(\w+=|$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wduser=({user_email}[^@\s]{1,2000}@({email_domain}[^\s@]{1,2000}))""",
    """\Wsuser=({user_email}[^@\s]{1,2000}@({email_domain}[^\s@]{1,2000}))""",
    """\Wsuid=({user_email}[^@\s]{1,2000}@({email_domain}[^\s@]{1,2000}))""",
    """\Woutcome=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){2}({app}[^\|]{1,2000})""",
  ]}
```