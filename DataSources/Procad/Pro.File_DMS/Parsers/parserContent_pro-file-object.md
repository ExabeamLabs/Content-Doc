#### Parser Content
```Java
{
Name = pro-file-object
  Vendor = Procad
  Product = Pro.File DMS
  Lms = Splunk
  DataType = "object-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [""""pdmobjectsubtypename":"""" , """"pdmobjecttypename":""""]
  Fields = [
     """autodatetime":"({time}[^"]+)""",
     """pdmobjecttypename":"({resource}[^"]+)""",
     """pdmusername":"({user}[^"]+)""",
     """pdmserverlocation":"({host}[^"]+)""",
     """pdmobjectsubtypename":"({object}[^"]+)""",
     """pdmobjectactionname":"({activity}[^"]+)"""
  ]
  DupFields = ["host->dest_host"]
}
```