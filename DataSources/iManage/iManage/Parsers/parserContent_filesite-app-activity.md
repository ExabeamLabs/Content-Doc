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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """ACTIVITY_DATETIME\s{0,100}=\s{0,100}({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """DOCNUM\s{0,100}=\s{0,100}({object}.+?)\s{1,100}(\w+\s{1,100}=|$)""",
    """ACTIVITY\s{0,100}=\s{0,100}({activity}.+?)\s{1,100}(\w+\s{1,100}=|$)""",
    """DOCUSER\s{0,100}=\s{0,100}({user}[^\s]{1,2000}?)\s{1,100}(\w+\s{1,100}=|$)""",
    """APPNAME\s{0,100}=\s{0,100}({additional_info}.+?)\s{1,100}(\w+\s{1,100}=|$)""",
    """LOCATION\s{0,100}=\s{0,100}({dest_host}[\w\-.]{1,2000})\s{1,100}(\w+\s{1,100}=|$)""",
    """DOCNAME\s{0,100}=\s{0,100}({resource}.+?)\s{1,100}(\w+\s{1,100}=|$)""",
    """DOCLOC\s{0,100}=\s{0,100}({file_path}({file_parent}.+?)[\\\/]{0,2000}({file_name}[^\\\/]{1,2000}?))\s{1,100}(\w+\s{1,100}=|$)""",
  ]
}
```