#### Parser Content
```Java
{
Name = json-dell-file-operations
  Vendor = Dell EMC Isilon
  Product = Dell EMC Isilon
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """SMB2""" , """eventType""" , """create""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+[\+\-]\d+:\d+)\s+({host}[\w\-.]+)\s+.+?protocol[":]+({protocol}[^"]+)[",]+zoneID[":]+({zone_id}[\d]+)[,"]+zoneName[:"]+[^"]+[",]+eventType[":]+({accesses}[^"]+)[",]+createResult[":]+({outcome}[^"]+).+?clientIPAddr[":]+({src_ip}[A-Fa-f:\d.]+)[",]+userSID[":]+({user_sid}[^"]+)[",]+userID[":]+({user}\d+)[,"]+"""
    """"fileName"*:"*({file_path}(({file_parent}[^"]+)[\\\/]+)?(({file_name}[^"\\\/]+?(\.({file_ext}[^\."]+))?)))"*,""" 
  ]
}
```