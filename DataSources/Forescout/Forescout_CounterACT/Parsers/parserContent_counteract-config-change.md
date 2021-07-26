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
    """(\w+\s{1,100}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})\s{1,100}({host}\S+)\s{1,100}Main Appliance""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """\sUser\s{1,100}({user}.+?)\s{1,100}session\s{1,100}({session_id}\d{1,100})\s{1,100}({activity}\w+)\s{1,100}({object}.+?)\.""",
    """\sDetails:\s{0,100}({additional_info}.+?)(\s{1,100}device\s{1,100}({dest_ip}[a-fA-F\d.:]{1,2000}))?\s{0,100}$""",
    """from\[({src_ip}[a-fA-F\d.:]{1,2000})\]\s{1,100}to\[({dest_ip}[a-fA-F\d.:]{1,2000})\]""",
  ]
}
```