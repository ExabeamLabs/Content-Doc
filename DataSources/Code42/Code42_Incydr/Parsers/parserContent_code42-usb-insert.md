#### Parser Content
```Java
{
Name = code42-usb-insert
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """formattedTimestamp""", """deviceAddress""", """deviceRemoteAddress""", """operatingSystemUser""", """"modular_input_consumption_time":""", """DEVICE_APPEARED""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"deviceAddress":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"deviceAddress":\s{0,100}"({src_ip}\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4})""",
    """"deviceRemoteAddress":\s{0,100}"({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"deviceRemoteAddress":\s{0,100}"({src_translated_ip}\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4})""",
    """"timestamp":\s{0,100}({time}\d\d\d\d\d\d\d\d\d\d)""",
    """"userUid":\s"({user_uid}[^"]{1,2000})""",
    """"eventType":\s"({activity}[^"]{1,2000})""",
    """"busType":\s"({device_type}[^"]{1,2000})""",
    """"deviceGuid":\s"({device_id}[^"]{1,2000})""",
    """"deviceName":\s"({device_name}[^"]{1,2000})""",
    """"mediaName":\s"({device_name}[^"]{1,2000})""",
    """"serialNumber":\s"(unknown|({usb_serial_number}[^"]{1,2000}))""",
    """"mediaName"":\s"({device_name}[^"]{1,2000})""",
    """"vendorName":\s"({vendor_name}[^"]{1,2000})""",
    """"vendorName":\s"({usb_vendor}[^"]{1,2000})""",
    """"volumeName":\s"(unknown|[^\(]{0,2000}?({drive_letter}[^"]{1,2000}))"""
  ]
}
```