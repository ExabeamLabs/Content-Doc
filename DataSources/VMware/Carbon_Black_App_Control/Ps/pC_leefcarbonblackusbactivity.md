#### Parser Content
```Java
{
Name = leef-carbonblack-usb-activity
  Vendor = VMware
  Product = Carbon Black App Control
  Lms = QRadar
  DataType = "usb-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Conditions = [ """LEEF:""", """|VMware_Carbon_Black|App_Control|""", """srcHostName =""", """policy=""", """dstHostName =""", """tached|""" ]
  Fields = [
    """devTime=({time}\w{1,3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d\.\d{1,3}\s\w{1,3})""",
    """\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})\sLEEF""",
    """\|App_Control\|[^\|]{1,2000}\|({activity}[^\|]{1,2000})""",
    """msg=Device\s{1,100}'({device_id}[^']{1,2000})'""",
    """msg=({activity_details}[^=]{1,2000}?)\.\s""",
    """sev=({severity}\d{1,100})""",
    """src=({src_ip}[a-fA-F\d:.]{1,2000})""",
    """srcHostName =(({domain}[^\\\s]{1,2000})\\{1,20})?({src_host}[^\s]{1,2000})""",
    """usrName =(({domain}[^\\\s]{1,2000})\\{1,20})?({user}[^\s]{1,2000})""",
    """dstHostName =({dest_host}[^\s]{1,2000})"""
  ]


}
```