#### Parser Content
```Java
{
Name = cef-db2-security-alert
  Vendor = IBM
  Product = IBM DB2
  Lms = ArcSight
  DataType = "alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Enterprise-IT-Security""", """|AppSec""", """ PCI_DB2 """ ]
  Fields = [
    """\s({time}\d+-\d+-\d+T\d+:\d+:\d+)\S*\s+({host}[\w\-.]+)\s+PCI_DB2""",
    """deviceProcessName=({host}[\w\-.]+)""",
    """act=({alert_name}.+?)\s+(\w+=|$)""",
    """cat=({category}.+?)\s+(\w+=|$)""",
    """cs2=({outcome}.+?)\s+(\w+=|$)""",
    """shost=({dest_host}[\w\-.]+)\s+(\w+=|$)""",
    """deviceProcessName=({process_name}.+?)\s+(\w+=|$)""",
    """cs1=({additional_info}.+?)\s+(\w+=|$)""",
    """duser=({user}.+?)\s*\w+=""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```