#### Parser Content
```Java
{
Name = cef-db2-file-read
  Vendor = IBM
  Product = IBM DB2
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Enterprise-IT-Security""", """|DB2_AU02|""", """|DB2Aud002_Access_To_PCI_Object|""", """ PCI_DB2 """ ]
  Fields = [
    """\s({time}\d+-\d+-\d+T\d+:\d+:\d+)\S*\s+({host}[\w\-.]+)\s+PCI_DB2""",
    """deviceProcessName=({host}[\w\-.]+)""",
    """act=({action}.+?)\s+(\w+=|$)""",
    """cat=({category}.+?)\s+(\w+=|$)""",
    """cs2=({outcome}.+?)\s+(\w+=|$)""",
    """shost=({src_host}[\w\-.]+)\s+(\w+=|$)""",
    """deviceProcessName=({process_name}.+?)\s+(\w+=|$)""",
    """cs1=({additional_info}.+?)\s+(\w+=|$)""",
    """cs3=({activity}.+?)\s+(\w+=|$)""",
    """filePath=({file_name}.+?)\s+(\w+=|$)""",
    """duser=({user}.+?)\s*\w+=""",
  ]
  DupFields = [ "file_name->object" ]
}
```