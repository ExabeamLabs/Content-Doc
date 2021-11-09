#### Parser Content
```Java
{
Name = cef-netapp-file-delete-2
  Product = NetApp
  DataType = file-operations
  Conditions = [ """|NetApp|NetApp-Security-Auditing|""", """|Delete Object Attempt|""" ]
}
cef-netapp-file-operations = {
  Vendor = NetApp
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wahost=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wahost=({host}[\w\-.]{1,2000})""",
    """\Wapp=({app}[^\s]{1,2000})\s""",
    """\Wcat=({category}[^\s]{1,2000})\s""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsuser=({user}[^\s]{1,2000})\s""",
    """\Wfname=({file_path}.+?)\s{0,100}(\w+=|$)""",
    """\Wfname=.*?({file_name}[^\\]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\Wfname=.*?(\.({file_ext}[^\\\.]{1,2000}?))?\s{0,100}(\w+=|$)""",
    """\WfileId=(-|({file_id}\d{1,100}))""",
    """filePath=({file_path}({file_parent}.+?)([\\\/]{0,2000}({file_name}[^\\\/]{1,2000}?))?)\s{1,100}(\w+=|$)""",
    """\WfileType=({file_type}.+?)\s{0,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){5}({accesses}[^\|]{1,2000})""",
    """\Wcs1=(-|({user_sid}.+?))\s{0,100}(\w+=|$)""",
    """\Woutcome=.+({outcome}Success|Failure)""",
    """CEF:([^\|]{0,2000}\|){6}((?i)unknown|({severity}[^\|]{1,2000}))""",
    """filePermission=({file_permissions}.+?)\s{0,100}cs1""",
  ]
 }}
```