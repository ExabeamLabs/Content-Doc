#### Parser Content
```Java
{
Name = cef-ruid-auth-success
  Vendor = RUID
  Product = RUID
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|BCA|RUID|""", """ cn1=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wcs3=({user}[^\s]{1,2000})""",
    """\Wcs4=({account}[^\s]{1,2000})""",
    """\Wcs5=({src_host}[\w\-.]{1,2000})""",
    """\Wcs5Label=({src_ip}[A-Fa-f:\d.]{1,2000}?)(:\d{1,100})?\s""",
    """\Wcn1=({admin_id}[^\s]{1,2000})""",
    """\WflexString2=({user_fullname}.+?)\s{1,100}(\w+=|$)""",
    """\Wdhost=({dest_host}[^\s]{1,2000})""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
  ]
}
```