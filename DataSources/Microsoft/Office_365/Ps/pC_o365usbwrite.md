#### Parser Content
```Java
{
Name = o365-usb-write
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """"RemovableMediaDeviceAttributes":""", """"FileCreatedOnRemovableMedia"""", """destinationServiceName =Office 365""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,7}Z)?)""",
    """"DeviceName":"(::ffff:)?({host}[\w\-.]{1,2000})"""",
    """"Operation":"({activity}[^"]{0,2000})"""",
    """"UserId":"(({user_email}[^@"]{1,2000}@[^"]{1,2000})|({user}[^"]{1,2000}))"""",
    """"ClientIP":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """"ObjectId":"({file_path}({file_parent}[^"]{1,2000}?)\\{1,20}({file_name}[^\\"]{1,2000}))"""",
    """"FileExtension":"({file_ext}[^"]{1,2000})"""",
    """"displayName":"({user_fullname}({user_firstname}[^\s"]{1,2000})\s({user_lastname}[^"]{1,2000}))""",
    """"SerialNumber":"({device_id}[^"]{1,2000})"""",
    """"Model":"({device_type}[^"]{1,2000})""""
  ]
  DupFields = ["activity->event_name", "host->dest_host", "file_name->src_file_name", "file_ext->src_file_ext"]


}
```