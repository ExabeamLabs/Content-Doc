#### Parser Content
```Java
{
Name = cef-azure-auth-failed
  Vendor = Microsoft
  Product = Microsoft Azure Active Directory
  Lms = ArcSight
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Azure Active Directory|""", """|PasswordLogonInitialAuthUsingPassword|""", """LoginError""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wrt=({time}\d+)""",
    """\Wact=({event_code}.+?)\s*(\w+=|$)""",
    """\Woutcome=({outcome}.+?)\s*(\w+=|$)""",
    """\Wsuid=(?!\S+@\S+)({user}[^\s]+)\s*(\w+=|$)""",
    """\Wsuid=({user_email}({user}[^\s@]+)@[^\s]+)\s*(\w+=|$)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
  ]
}
```