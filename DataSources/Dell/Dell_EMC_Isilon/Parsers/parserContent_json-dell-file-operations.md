#### Parser Content
```Java
{
Name = json-dell-file-operations
  Vendor = Dell
  Product = Dell EMC Isilon
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """SMB2""" , """eventType""" , """create""" ]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100})\s{1,100}({host}[\w\-.]+)\s{1,100}.+?protocol[":]+({protocol}[^"]+)[",]+zoneID[":]+({zone_id}[\d]+)[,"]+zoneName[:"]+[^"]+[",]+eventType[":]+({accesses}[^"]+)[",]+createResult[":]+({outcome}[^"]+).+?clientIPAddr[":]+({src_ip}[A-Fa-f:\d.]+)[",]+userSID[":]+({user_sid}[^"]+)[",]+userID[":]+({user}\d{1,100})[,"]+"""
    """"fileName"{0,20}:"{0,20}({file_path}(({file_parent}[^"]+)[\\\/]+)?(({file_name}[^"\\\/]+?(\.({file_ext}[^\."]+))?)))"{0,20}
```