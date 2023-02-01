#### Parser Content
```Java
{
Name = cef-trendmicro-visionone-alert
  Vendor = Trend Micro
  Product = Vision One
  Lms = Direct
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Trend Micro|Vision One|""", """900002|Vision One Observed Attack Technique|""" ]
  Fields = [
    """rt=({time}\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){4}({event_code}[^|]{1,2000})""",
    """cat=((?i)Unknown|({alert_type}[^=,]{1,2000}))(\s{0,10

}
```