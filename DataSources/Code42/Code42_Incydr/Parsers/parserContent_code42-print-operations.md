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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"eventTimestamp"{1,20}:\s{0,100}"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """"eventType"{1,20}:\s{0,100}"{1,20}({event_code}[^"]+)""",
    """"source":"{1,20}({log_source}[^"]+)"""",
    """"userUid"{1,20}:\s{0,100}"{1,20}({user_uid}[^"]+)"""",
    """"deviceUid"{1,20}:\s{0,100}"{1,20}({device_id}[^"]+)"""",
    """"processOwner"{1,20}:\s{0,100}"{1,20}({user}[^"]+)"""",
    """"deviceUserName"{1,20}:\s{0,100}"{1,20}({user_email}[^@"]+@[^"]+)"""",
    """"osHostName"{1,20}:\s{0,100}"{1,20}({dest_host}[^"]+)"""",
    """"actor"{1,20}:"{1,20}(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))""",
    """"publicIpAddress":"{1,20}({dest_ip}[^"]+)"""",
    """"privateIpAddresses":\[*"{1,20}({src_ip}[^"]+)"""",
    """"printerName":"{1,20}({printer_name}[^"]+)"""",
    """"printJobName":"{1,20}\s{0,100}({object}[^"]+)"""",
  ]
  DupFields = ["dest_host->device_name"]
}
```