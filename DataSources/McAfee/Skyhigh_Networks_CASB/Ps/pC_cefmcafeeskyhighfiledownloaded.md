#### Parser Content
```Java
{
Name = cef-mcafee-skyhigh-file-downloaded
    Vendor = McAfee
    Product = Skyhigh Networks CASB
    Lms = ArcSight
    DataType = "file-operations"
    TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
    Conditions = [ """CEF:""", """Skyhigh Security""", """|Anomalies""", """|AnomalousAccessLocation|Alert.Access|""", """File downloaded""" ]
    Fields = [
      """\d\d:\d\d:\d\d\s({host}[\w.\-]{1,2000})\s{1,100}CEF""",
      """end=({time}\w{3} \d{1,100} \d{1,100} \d\d:\d\d:\d\d\.\d{3} \w{3})""",
      """suser=(N\/A|system:anonymous|({user_email}[^@=]{1,2000}?@[^@=]{1,2000}?)|({user}[^\s=]{1,2000}?))\s""",
      """({event_name}File downloaded)""",
      """cs4=\[({dest_ip}[A-Fa-f\d.:]{1,2000})\]"""
    ]
 

}
```