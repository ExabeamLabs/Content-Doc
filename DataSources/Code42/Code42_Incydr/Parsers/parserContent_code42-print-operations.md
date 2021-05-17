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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventTimestamp"{1,20}:\s{0,100}"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """"eventType"{1,20}:\s{0,100}"{1,20}({event_code}[^"]{1,2000})""",
    """"source":"{1,20}({log_source}[^"]{1,2000})"""",
    """"userUid"{1,20}:\s{0,100}"{1,20}({user_uid}[^"]{1,2000})"""",
    """"deviceUid"{1,20}:\s{0,100}"{1,20}({device_id}[^"]{1,2000})"""",
    """"processOwner"{1,20}:\s{0,100}"{1,20}({user}[^"]{1,2000})"""",
    """"deviceUserName"{1,20}:\s{0,100}"{1,20}({user_email}[^@"]{1,2000}@[^"]{1,2000})"""",
    """"osHostName"{1,20}:\s{0,100}"{1,20}({dest_host}[^"]{1,2000})"""",
    """"actor"{1,20}:"{1,20}(({user_email}[^"@]{1,2000}@[^"@]{1,2000})|({user}[^"]{1,2000}))""",
    """"publicIpAddress":"{1,20}({dest_ip}[^"]{1,2000})"""",
    """"privateIpAddresses":\[*"{1,20}({src_ip}[^"]{1,2000})"""",
    """"printerName":"{1,20}({printer_name}[^"]{1,2000})"""",
    """"printJobName":"{1,20}\s{0,100}({object}[^"]{1,2000})"""",
  ]
  DupFields = ["dest_host->device_name"]
}
```