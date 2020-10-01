#### Parser Content
```Java
{
Name = counteract-config-change
  Vendor = Forescout
  Product = Forescout CounterACT
  Lms = Direct
  DataType = "config-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ User """, """ session """, """ Details: """, """ Main Appliance[""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(\w+\s+\d+ \d+:\d+:\d+)\s+({host}\S+)\s+Main Appliance""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """\sUser\s+({user}.+?)\s+session\s+({session_id}\d+)\s+({activity}\w+)\s+({object}.+?)\.""",
    """\sDetails:\s*({additional_info}.+?)(\s+device\s+({dest_ip}[a-fA-F\d.:]+))?\s*$""",
    """from\[({src_ip}[a-fA-F\d.:]+)\]\s+to\[({dest_ip}[a-fA-F\d.:]+)\]""",
  ]
}
```