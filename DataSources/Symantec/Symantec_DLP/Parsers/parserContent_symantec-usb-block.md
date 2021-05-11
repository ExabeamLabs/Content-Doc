#### Parser Content
```Java
{
Name = symantec-usb-block
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Splunk
    DataType = "usb-insert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ ",Blocked,", ",Begin:", ",Action Type:", ",Device ID:" ]
    Fields = [ """exabeam_host=({host}[^,\s]+)""",
      """SymantecServer:\s{0,100}({host}[\w\-.]+)""",
      """(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s,]+)),Blocked,""",
      """Begin:\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Rule: [^,]*,\d{1,100}
```