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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\sraw_g_hostname="{1,20}({dest_host}[^"]{1,2000})"{1,20},""",
    """\sraw_event_id="{1,20}({activity}[^"]{1,2000})"{1,20},""",
    """\sraw_ntuser="{1,20}(?:({domain}\w+)\\)?({user}[^"]{1,2000}?)"""",
    """\sraw_aduser="{1,20}(?=\w)({account_dn}.+?)"""",
    """\|devicename=({device_id}[^,\|]{1,2000})""",
    """\|devicename=([^,]{1,2000}),\s{1,100}({device_type}[^,;]{1,2000}),\s{1,100}""",
    """\|filesize=({hex_bytes}[^\|]{1,2000})""",
    """\|path=+(?=\w)({file_path}.+?)\|""",
    """path=.*\\({file_name}(?:[^\\|]{1,2000}(?=\.))({file_ext}\.[^\\|]{1,2000})?|[^\\|]{1,2000})\|\w+=""",
    """\|processname=+(?=\w)({process_name}.+?)\|""",
    """\|reason=+(?=\w)({activity_details}.+?)\|"""
  ]
}
```