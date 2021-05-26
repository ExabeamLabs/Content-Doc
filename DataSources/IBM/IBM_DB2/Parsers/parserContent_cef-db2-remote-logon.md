#### Parser Content
```Java
{
Name = cef-db2-remote-logon
  Vendor = IBM
  Product = IBM DB2
  Lms = ArcSight
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Enterprise-IT-Security""", """|DB2_AU05|""", """|DB2Aud005_Login_Logout_Activity|""", """ PCI_DB2 """ ]
  Fields = [
    """\s({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})\S*\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}PCI_DB2""",
    """deviceProcessName=({host}[\w\-.]{1,2000})""",
    """act=({action}.+?)\s{1,100}(\w+=|$)""",
    """cat=({category}.+?)\s{1,100}(\w+=|$)""",
    """dproc=({object}.+?)\s{1,100}(\w+=|$)""",
    """cs2=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """shost=({src_host}[\w\-.]{1,2000})\s{1,100}(\w+=|$)""",
    """deviceProcessName=({process_name}.+?)\s{1,100}(\w+=|$)""",
    """cs1=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """duser=({user}.+?)\s{0,100}\w+=""",
    """({event_code}DB2_AU05)""",
    """({event_name}DB2Aud005_Login_Logout_Activity)""",
  ]
}
```