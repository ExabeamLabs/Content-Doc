#### Parser Content
```Java
{
Name = code42-print-operations
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss:SSZ"
  Conditions= [ """"fileCategoryByExtension"""",  """"eventType":"PRINTED"""", """"osHostName"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventTimestamp"+:\s*"+({time}\d+-\d+-\d+T\d+:\d+:\d+Z)""",
    """"eventType"+:\s*"+({event_code}[^"]+)""",
    """"source":"+({log_source}[^"]+)"""",
    """"userUid"+:\s*"+({user_uid}[^"]+)"""",
    """"deviceUid"+:\s*"+({device_id}[^"]+)"""",
    """"processOwner"+:\s*"+({user}[^"]+)"""",
    """"deviceUserName"+:\s*"+({user_email}[^@"]+@[^"]+)"""",
    """"osHostName"+:\s*"+({dest_host}[^"]+)"""",
    """"actor"+:"+(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))""",
    """"publicIpAddress":"+({dest_ip}[^"]+)"""",
    """"privateIpAddresses":\[*"+({src_ip}[^"]+)"""",
    """"printerName":"+({printer_name}[^"]+)"""",
    """"printJobName":"+\s*({object}[^"]+)"""",
  ]
  DupFields = ["dest_host->device_name"]
}
```