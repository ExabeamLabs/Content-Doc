#### Parser Content
```Java
{
Name = crowdstrike-usb-insert
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "usb-activity"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"RemovableMediaVolumeMounted""""]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"+aip"+:"+({host}[^"]+)"+,"""
      """"timestamp":"({time}\d+)""",
      """"event_simpleName":"({event_code}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"VolumeRealDeviceName":"({device_type}[^"]+)""",
      """VolumeMountPoint":"\\\\\?\?\\\\Volume\{({device_id}[^}]+)""",
      """suser=(system|({user}[^\s]+))""",
      """DiskParentDeviceInstanceId"+:"+USB\\+VID_({vendor_id}[^&]+)&PID_({pid}[^\\&]+).*?\\+({device_id}[^"]+)""",
    ]
    DupFields = [ "pid->process_name", "device_type->volume_name" ]
  }
```