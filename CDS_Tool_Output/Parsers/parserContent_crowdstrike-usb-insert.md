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
      """({host}[\w\-.]+)\s+Skyformation""",
      """"timestamp":"({time}\d+)""",
      """"event_simpleName":"({event_code}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"VolumeRealDeviceName":"({device_type}[^"]+)""",
      """VolumeMountPoint":"\\\\\?\?\\\\Volume\{({device_id}[^}]+)"""
    ]
  }
```