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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """art=({time}\d{1,100})""",
    """shost=({src_host}[^\s]{1,2000})\s""",
    """msg=({activity}[^\s]{1,2000})""",
    """\|Device Control Event\|({priority}[^|]{1,2000})\|""",
    """src=({src_ip}[A-Fa-f\d.:]{1,2000})""",
    """cs1=({device_type}[^\s]{1,2000})""",
    """cs2=({device_name}[^\s]{1,2000})""",
    """cs3=({device_id}[^\s]{1,2000})""",
    """sourceServiceName=({user_sid}[^\s]{1,2000})""",
    """suser=({user}[^\s]{1,2000})""",
  ]
}
```