#### Parser Content
```Java
{
Name = cef-mcafee-skyhigh-dlp-alert-1
    Vendor = McAfee
    Product = Skyhigh Networks CASB
    Lms = ArcSight
    DataType = "dlp-alert"
    TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
    Conditions = [ """CEF:""", """Skyhigh Security""", """|Anomalies""", """|Dlp|Alert.Policy|""" ]
    Fields = [
      """\d\d:\d\d:\d\d\s({host}[\w.\-]{1,2000})\s{1,100}CEF""",
      """CEF:([^\|]{0,2000}\|){5}({alert_type}[^\|\s]{1,2000})\|""",
      """end=({time}\w{3} \d{1,100} \d{1,100} \d\d:\d\d:\d\d\.\d{3} \w{3})""",
      """suser=(N\/A|({user_email}[^@=]{1,2000}?@[^@=]{1,2000}?)|({user}(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\s]{1,2000}?))\s""",
      """CEF([^\|]{0,2000}\|){6}({alert_severity}[^|]{1,2000})""", 
      """cs1=\[({outcome}[^\]]{1,2000})[^~]{1,2000}?cs1Label=Responses""",
      """flexString2=({alert_id}[^\s]{1,2000})[^~]{1,2000}?flexString2Label=incidentId""",
      """cs6=\[({activity}[^\s\]]{1,2000})[^~]{1,2000}?cs6Label=Activity""",
      """instanceName =({src_host}[^\s]{1,2000}?)\s""",
      """fname=({file_name}[^=]{1,2000}?(\.({file_ext}[^\s=.]{1,2000}))?)\s\w+=""",
    ]
 

}
```