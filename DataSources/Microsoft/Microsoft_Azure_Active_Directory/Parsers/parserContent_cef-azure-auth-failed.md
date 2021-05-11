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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wact=({event_code}.+?)\s{0,100}(\w+=|$)""",
    """\Woutcome=({outcome}.+?)\s{0,100}(\w+=|$)""",
    """\Wsuid=(?!\S+@\S+)({user}[^\s]+)\s{0,100}(\w+=|$)""",
    """\Wsuid=({user_email}({user}[^\s@]+)@[^\s]+)\s{0,100}(\w+=|$)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
  ]
}
```