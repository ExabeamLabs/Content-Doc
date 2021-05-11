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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wact=({event_code}.+?)\s{0,100}(\w+=|$)""",
    """\Woutcome=({outcome}.+?)\s{0,100}(\w+=|$)""",
    """\Wsuid=(?!\S+@\S+)({user}[^\s]+)\s{0,100}(\w+=|$)""",
    """\Wsuid=({user_email}({user}[^\s@]+)@[^\s]+)\s{0,100}(\w+=|$)""",
    """\Wcs5=.+?\|/Target/ID:"({target_user}[^"]+)"""
  ]
}
```