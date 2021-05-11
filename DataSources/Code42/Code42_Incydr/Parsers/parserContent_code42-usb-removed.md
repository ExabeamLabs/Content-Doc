#### Parser Content
```Java
{
Name = code42-usb-removed
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """formattedTimestamp""", """deviceAddress""", """deviceRemoteAddress""", """operatingSystemUser""", """"modular_input_consumption_time":""", """DEVICE_DISAPPEARED""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"deviceAddress":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"deviceAddress":\s{0,100}"({src_ip}\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4})""",
    """"deviceRemoteAddress":\s{0,100}"({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"deviceRemoteAddress":\s{0,100}"({src_translated_ip}\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4})""",
    """"timestamp":\s{0,100}({time}\d\d\d\d\d\d\d\d\d\d)""",
    """"userUid":\s"({user_uid}[^"]+)""",
    """"eventType":\s"({activity}[^"]+)""",
    """"busType":\s"({device_type}[^"]+)""",
    """"deviceGuid":\s"({device_id}[^"]+)""",
    """"deviceName":\s"({device_name}[^"]+)""",
    """"mediaName":\s"({device_name}[^"]+)""",
    """"serialNumber":\s"(unknown|({usb_serial_number}[^"]+))""",
    """"mediaName"":\s"({device_name}[^"]+)""",
    """"vendorName":\s"({vendor_name}[^"]+)""",
    """"vendorName":\s"({usb_vendor}[^"]+)""",
    """"volumeName":\s"(unknown|[^\(]*?({drive_letter}[^"]+))"""
  ]
}
```