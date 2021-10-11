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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"{1,20}aip"{1,20}:"{1,20}({host}[^"]{1,2000})"{1,20},"""
      """"timestamp":"({time}\d{1,100})"""",
      """"event_simpleName":"({event_code}[^"]{1,2000})""",
      """"aid":"({aid}[^"]{1,2000})""",
      """"VolumeRealDeviceName":"({device_type}[^"]{1,2000})""",
      """VolumeMountPoint":"\\\\\?\?\\\\Volume\{({device_id}[^}]{1,2000})""",
      """suser=(system|({user}[^\s]{1,2000}))""",
      """DiskParentDeviceInstanceId"{1,20}:"{1,20}USB\\+VID_({vendor_id}[^&]{1,2000})&PID_({pid}[^\\&]{1,2000}).*?\\+({device_id}[^"]{1,2000})""",
    ]
    DupFields = [ "pid->process_name", "device_type->volume_name", "event_code->activity" ]
  }
```