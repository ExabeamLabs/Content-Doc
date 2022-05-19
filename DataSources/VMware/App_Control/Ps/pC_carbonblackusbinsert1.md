#### Parser Content
```Java
{
Name = carbonblack-usb-insert-1
  Vendor = VMware
  Product = App Control
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """Carbon Black App Control event:""", """subtype="Device attached""", """ ip_address=""" ]
  Fields = [
    """\sdate="({time}\d{1,2}\/\d{1,2}\/\d{1,4}\s\d{1,2}:\d{1,2}:\d{1,2}\s(am|AM|PM|pm))"""",
    """\shostname="(({domain}[^\\]{1,2000})\\({host}[^"]{1,2000}))"""",
    """\ssubtype="({activity}[^"]{1,2000})"""",
    """\stext="({activity_details}[^"]{1,2000}?)\s{0,10}"""",
    """\sip_address="({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\spolicy="({event_name}[^"]{1,2000})"""",
    """\(S\/N:\s{0,10}({device_id}[^\)]{1,2000})\)""",
    ]


}
```