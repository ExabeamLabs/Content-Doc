#### Parser Content
```Java
{
Name = code42-file-operations-2
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "epoch"
  Conditions= [ """formattedTimestamp""", """deviceAddress""", """deviceRemoteAddress""", """operatingSystemUser""", """"fileEventType":""", """"modular_input_consumption_time":"""]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """processOwner"\s{0,100}:\s{0,100}"({user}[^"]{1,2000})""",
    """"fileOwnerUsername":\s{0,100}"(\w+\\+)?({user}[^"]{1,2000})""",
    """"deviceAddress":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"deviceAddress":\s{0,100}"({src_ip}\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4})""",
    """"deviceRemoteAddress":\s{0,100}"({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"deviceRemoteAddress":\s{0,100}"({src_translated_ip}\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4})""",
    """"fileName":\s{0,100}"({file_name}[^"]{1,2000})""",
    """"fileEventType":\s{0,100}"({accesses}[^"]{1,2000})""",
    """"fileType":\s{0,100}"({file_type}[^"]{1,2000})""",
    """"detectionTimestamp":\s{0,100}({time}\d\d\d\d\d\d\d\d\d\d\d\d\d)""",
    """"processName":\s{0,100}"({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}?))"""",
    """"fullPath":\s{0,100}"({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?))"""",
    """"md5":\s"({md5_sum}[^"]{1,2000})""",
    """"sha256":\s"({sha256_sum}[^"]{1,2000})""",
    """"userUid":\s"({user_uid}[^"]{1,2000})""",
  ]
}
```