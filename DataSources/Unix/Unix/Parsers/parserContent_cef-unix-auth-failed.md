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
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wsuser=({user}[^\s]+?)\s+(\w+=|$)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wahost=(({src_ip}[A-Fa-f:\d.]+)|({src_host}[\w\-.]+))""",
    """\Wagt=({src_ip}[A-Fa-f:\d.]+)""",
    """\WcategoryOutcome=\/?({outcome}.+?)\s+(\w+=|$)""",
  ]
}
```