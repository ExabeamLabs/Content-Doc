#### Parser Content
```Java
{
Name = crowdstrike-falcon-usb-write-1
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ """"destinationServiceName":"CrowdStrike"""" ,""""IsOnRemovableDisk":"1"""", """"event_simpleName":""", """Written"""" ]
  Fields = [
    """"timestamp":"({time}\d{13})"""",
    """"UserName":"({user}[^"]{1,2000})"""",
    """"aip":"({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """"name":"({event_name}[^"]{1,2000})"""",
    """"event_simpleName":"({event_code}[^"]{1,2000})"""",
    """"TargetFileName":"({file_path}(({file_parent}[^"]{0,2000}?)[\\\/]{1,2000})?\s{0,100}({file_name}[^\\\/"]{1,2000}?(\.(\d{1,20}|({file_ext}[^\\\/"\.]{1,2000}?)))?))\s{0,100}"""",
    """"Size":"({bytes}\d{1,20})"""",
    """"DiskParentDeviceInstanceId":"({device_id}[^"]{1,2099})"""",
    """"aid":"({aid}[^"]{1,2000})""""
  ]
  DupFields = [ "device_id->service_type" ]


}
```