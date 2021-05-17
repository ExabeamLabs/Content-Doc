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
     """autodatetime":"({time}[^"]{1,2000})""",
     """pdmobjecttypename":"({resource}[^"]{1,2000})""",
     """pdmusername":"({user}[^"]{1,2000})""",
     """pdmserverlocation":"({host}[^"]{1,2000})""",
     """pdmobjectsubtypename":"({object}[^"]{1,2000})""",
     """pdmobjectactionname":"({activity}[^"]{1,2000})"""
  ]
  DupFields = ["host->dest_host"]
}
```