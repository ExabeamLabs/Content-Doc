#### Parser Content
```Java
{
Name = json-dell-file-operations
  Vendor = Dell
  Product = EMC Isilon
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """SMB2""" , """eventType""" , """create""" ]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100})\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}.+?protocol[":]{1,2000}({protocol}[^"]{1,2000})[",]{1,2000}zoneID[":]{1,2000}({zone_id}[\d]{1,2000})[,"]{1,2000}zoneName[:"]{1,2000}[^"]{1,2000}[",]{1,2000}eventType[":]{1,2000}({accesses}[^"]{1,2000})[",]{1,2000}createResult[":]{1,2000}({outcome}[^"]{1,2000}).+?clientIPAddr[":]{1,2000}({src_ip}[A-Fa-f:\d.]{1,2000})[",]{1,2000}userSID[":]{1,2000}({user_sid}[^"]{1,2000})[",]{1,2000}userID[":]{1,2000}({user}\d{1,100})[,"]{1,2000}"""
    """"fileName"{0,20}:"{0,20}({file_path}(({file_parent}[^"]{1,2000})[\\\/]{1,2000})?(({file_name}[^"\\\/]{1,2000}?(\.({file_ext}[^\."]{1,2000}))?)))"{0,20

}
```