#### Parser Content
```Java
{
Name = cef-unix-auth-failed
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """Unix|Unix""", """|password check failed|""", """categoryOutcome=/Failure""", """unix_chkpwd""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wsuser=({user}[^\s]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wahost=(({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[\w\-.]{1,2000}))""",
    """\Wagt=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WcategoryOutcome=\/?({outcome}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```