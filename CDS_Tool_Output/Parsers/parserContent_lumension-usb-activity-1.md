#### Parser Content
```Java
{
Name = lumension-usb-activity-1
  Vendor = Lumension
  Product = Lumension
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "epoch"
  Conditions = ["""CEF:""", """|Lumension|""" , """|Lumension Device Control|"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """art=({time}\d+)""",
    """shost=({src_host}[^\s]+)\s""",
    """msg=({activity}[^\s]+)""",
    """\|Device Control Event\|({priority}[^|]+)\|""",
    """src=({src_ip}[A-Fa-f\d.:]+)""",
    """cs1=({device_type}[^\s]+)""",
    """cs2=({device_name}[^\s]+)""",
    """cs3=({device_id}[^\s]+)""",
    """sourceServiceName=({user_sid}[^\s]+)""",
    """suser=({user}[^\s]+)""",
  ]
}
```