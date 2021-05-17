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
    """\s({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})\S*\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}PCI_DB2""",
    """deviceProcessName=({host}[\w\-.]{1,2000})""",
    """act=({action}.+?)\s{1,100}(\w+=|$)""",
    """cat=({category}.+?)\s{1,100}(\w+=|$)""",
    """cs2=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """shost=({src_host}[\w\-.]{1,2000})\s{1,100}(\w+=|$)""",
    """deviceProcessName=({process_name}.+?)\s{1,100}(\w+=|$)""",
    """cs1=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """cs3=({activity}.+?)\s{1,100}(\w+=|$)""",
    """filePath=({file_name}.+?)\s{1,100}(\w+=|$)""",
    """duser=({user}.+?)\s{0,100}\w+=""",
  ]
  DupFields = [ "file_name->object" ]
}
```