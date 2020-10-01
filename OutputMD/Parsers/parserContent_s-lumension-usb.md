#### Parser Content
```Java
{
Name = s-lumension-usb
  Vendor = Lumension
  Product = Lumension
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "raw_event_id" , "raw_g_hostname" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """\sraw_g_hostname="+({dest_host}[^"]+)"+,""",
    """\sraw_event_id="+({activity}[^"]+)"+,""",
    """\sraw_ntuser="+(?:({domain}\w+)\\)?({user}[^"]+?)"""",
    """\sraw_aduser="+(?=\w)({account_dn}.+?)"""",
    """\|devicename=({device_id}[^,\|]+)""",
    """\|devicename=([^,]+),\s+({device_type}[^,;]+),\s+""",
    """\|filesize=({hex_bytes}[^\|]+)""",
    """\|path=+(?=\w)({file_path}.+?)\|""",
    """path=.*\\({file_name}(?:[^\\|]+(?=\.))({file_ext}\.[^\\|]+)?|[^\\|]+)\|\w+=""",
    """\|processname=+(?=\w)({process_name}.+?)\|""",
    """\|reason=+(?=\w)({activity_details}.+?)\|"""
  ]
}
```