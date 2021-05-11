#### Parser Content
```Java
{
Name = symantec-usb-read
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,Rule:""", """,File Read,Begin:""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """Begin:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d{1,100} \d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]+)""",
    """,(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^,]*)),([^,]*,){2}File Read""",
    """Rule:[^\|]*\|\s{0,100}({activity_details}[^,]+)""",
    """User:\s{0,100}(SYSTEM|({user}[^\s,]+))""",
    """Domain:\s{0,100}({domain}[^,]+)""",
    """,File Read,([^,]*,){3}\d{1,100}
```