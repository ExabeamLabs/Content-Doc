#### Parser Content
```Java
{
Name = syslog-symantec-usb-write
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "epoch"
  Conditions = [ "Log files written to USB drives", "File Write", """|Symantec|Endpoint Protection|"""]
  Fields = [
    """\srt=({time}\d+)""",
    """exabeam_host=({host}[^,\s]+)""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sduser=({user}.+?)\s\w+=""",
    """\sdproc=Process Name:\s+(?: |({process}({directory}(?:[^=]+)?[\\\/])?({process_name}[^\\\/]+?)))\s\w+=""",
    """\scs1=.+?\| ({activity_details}.+?)\s\w+=""",
    """\sfilePath=({file_path}.+?)\s\w+=""",
    """\sfilePath=[^=]*\/({file_name}[^\/]*?)\s\w+=""",
    """({activity}File Write)""",
    """\sfsize=({bytes}\d+)""",
    """DEVICE__ID=({device_id}.*?)&\d+""",
    """({device_type}(CD-DVD|USB))"""
  ]
  DupFields = ["directory->process_directory"]
}
```