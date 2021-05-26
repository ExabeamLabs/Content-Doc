#### Parser Content
```Java
{
Name = cef-db2-security-alert-2
  Vendor = IBM
  Product = IBM DB2
  Lms = ArcSight
  DataType = "alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Enterprise-IT-Security""", """Security_System_Attack""" ]
  Fields = [
    """\s({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})\S*\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\w+\s""",
    """deviceProcessName=({host}[\w\-.]{1,2000})""",
    """act=({alert_name}.+?)\s{1,100}(\w+=|$)""",
    """cat=({category}.+?)\s{1,100}(\w+=|$)""",
    """cs2=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """shost=({dest_host}[\w\-.]{1,2000})\s{1,100}(\w+=|$)""",
    """deviceProcessName=({process_name}.+?)\s{1,100}(\w+=|$)""",
    """cs1=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """duser=({user}.+?)\s{0,100}\w+=""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```