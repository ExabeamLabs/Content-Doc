#### Parser Content
```Java
{
Name = cef-db2-auth-failed
  Vendor = IBM
  Product = IBM DB2
  Lms = ArcSight
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Enterprise-IT-Security""", """|DB2_AU07|""", """|DB2Aud007_Authorization_Failure|""", """ PCI_DB2 """ ]
  Fields = [
    """\s({time}\d+-\d+-\d+T\d+:\d+:\d+)\S*\s+({host}[\w\-.]+)\s+PCI_DB2""",
    """deviceProcessName=({host}[\w\-.]+)""",
    """act=({action}.+?)\s+(\w+=|$)""",
    """cat=({category}.+?)\s+(\w+=|$)""",
    """dproc=({object}.+?)\s+(\w+=|$)""",
    """cs2=({outcome}.+?)\s+(\w+=|$)""",
    """shost=({src_host}[\w\-.]+)\s+(\w+=|$)""",
    """deviceProcessName=({process_name}.+?)\s+(\w+=|$)""",
    """cs1=({additional_info}.+?)\s+(\w+=|$)""",
    """cn1=({failure_reason}[^:,]+?)(:[^=]*?)?\s+(\w+=|$)""",
    """cs3=({accesses}.+?)\s+(\w+=|$)""",
    """duser=({user}.+?)\s*\w+=""",
    """({event_code}DB2_AU07)""",
  ]
}
```