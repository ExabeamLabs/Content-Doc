#### Parser Content
```Java
{
Name = cef-azure-password-change
  Vendor = Microsoft
  Product = Microsoft Azure Active Directory
  Lms = ArcSight
  DataType = "password-change"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Azure Active Directory|""", """|Change user password|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wrt=({time}\d+)""",
    """\Wact=({event_code}.+?)\s*(\w+=|$)""",
    """\Woutcome=({outcome}.+?)\s*(\w+=|$)""",
    """\Wsuid=(?!\S+@\S+)({user}[^\s]+)\s*(\w+=|$)""",
    """\Wsuid=({user_email}({user}[^\s@]+)@[^\s]+)\s*(\w+=|$)""",
    """\Wcs5=.+?\|/Target/ID:"({target_user}[^"]+)""",
  ]
}
```