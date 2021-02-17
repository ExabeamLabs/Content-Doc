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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wrt=({time}\d+)""",
    """\Wcs3=({user}[^\s]+)""",
    """\Wcs4=({account}[^\s]+)""",
    """\Wcs5=({src_host}[\w\-.]+)""",
    """\Wcs5Label=({src_ip}[A-Fa-f:\d.]+?)(:\d+)?\s""",
    """\Wcn1=({admin_id}[^\s]+)""",
    """\WflexString2=({user_fullname}.+?)\s+(\w+=|$)""",
    """\Wdhost=({dest_host}[^\s]+)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
  ]
}
```