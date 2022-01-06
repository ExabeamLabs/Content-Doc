#### Parser Content
```Java
{
Name = cef-exchange-scanmail-alert
  Vendor = Trend Micro
  Product = ScanMail
  Lms = Direct
  DataType = "security-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Trend Micro|SMEX|""", """|100104|Web Threat Detection|""" ]
  Fields = [
    """rt=({time}\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
    """\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d-\d\d:\d\d\s{1,10}({host}[^\s]+)""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({alert_type}[^|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){4}({event_code}[^|]{1,2000})""",
    """cat=((?i)Unknown|({alert_type}[^=,]{1,2000}))(\s{0,10

}
```