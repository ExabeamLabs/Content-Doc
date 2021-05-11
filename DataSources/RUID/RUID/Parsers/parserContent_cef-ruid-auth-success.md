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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wcs3=({user}[^\s]+)""",
    """\Wcs4=({account}[^\s]+)""",
    """\Wcs5=({src_host}[\w\-.]+)""",
    """\Wcs5Label=({src_ip}[A-Fa-f:\d.]+?)(:\d{1,100})?\s""",
    """\Wcn1=({admin_id}[^\s]+)""",
    """\WflexString2=({user_fullname}.+?)\s{1,100}(\w+=|$)""",
    """\Wdhost=({dest_host}[^\s]+)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
  ]
}
```