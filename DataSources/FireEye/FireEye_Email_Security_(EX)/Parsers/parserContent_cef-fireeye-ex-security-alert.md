#### Parser Content
```Java
{
Name = cef-fireeye-ex-security-alert
  Vendor = FireEye
  Product = FireEye Email Security (EX)
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|FireEye|""", """flexString2Label=subject""", """|CMS|""", """fileType=""" ]
  Fields = [
     """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """rt=({time}[a-zA-Z]{3} \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
     """act=({action}[^=]{1,2000}?)\s{0,100}\w+=""",
     """externalId=({alert_id}\d{1,100})""",
     """\|FireEye\|([^\|]{1,2000}\|){3}({alert_name}[^\|]{1,2000})\|""",
     """\scs1Label=sname cs1=({alert_name}[^\s]{1,2000})""",
     """\|FireEye\|([^\|]{1,2000}\|){3}({alert_type}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})\|""",
     """\sdhost=({dest_host}\S+)""",
     """\scs5Label=cncHost cs5=(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]{1,2000}))""",
     """\sdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
     """\sfname=(?:[^,]{1,2000}
```