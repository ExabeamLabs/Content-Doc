#### Parser Content
```Java
{
Name = filesite-app-activity
  Vendor = iManage
  Product = iManage
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "dd/MM/yyyy HH:mm:ss"
  Conditions = [ """ ACTIVITY = """, """ ACTIVITY_DATETIME = """, """ DOCNUM = """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """ACTIVITY_DATETIME\s*=\s*({time}\d+\/\d+\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """DOCNUM\s*=\s*({object}.+?)\s+(\w+\s+=|$)""",
    """ACTIVITY\s*=\s*({activity}.+?)\s+(\w+\s+=|$)""",
    """DOCUSER\s*=\s*({user}[^\s]+?)\s+(\w+\s+=|$)""",
    """APPNAME\s*=\s*({additional_info}.+?)\s+(\w+\s+=|$)""",
    """LOCATION\s*=\s*({dest_host}[\w\-.]+)\s+(\w+\s+=|$)""",
    """DOCNAME\s*=\s*({resource}.+?)\s+(\w+\s+=|$)""",
    """DOCLOC\s*=\s*({file_path}({file_parent}.+?)[\\\/]*({file_name}[^\\\/]+?))\s+(\w+\s+=|$)""",
  ]
}
```