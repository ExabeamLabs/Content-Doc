#### Parser Content
```Java
{
Name = cef-mcafee-skyhigh-security-alert
    Vendor = McAfee
    Product = Skyhigh Networks CASB
    Lms = ArcSight
    DataType = "alert"
    TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
    Conditions = [ """CEF:""", """Skyhigh Security""", """|Anomalies""", """|Superhuman|Alert.Access|""" ]
    Fields = [
      """\d\d:\d\d:\d\d\s({host}[\w.\-]{1,2000})\s{1,100}CEF""",
      """end=({time}\w{3} \d{1,100} \d{1,100} \d\d:\d\d:\d\d\.\d{3} \w{3})""",
      """suser=(N\/A|system:anonymous|({user_email}[^@=]{1,2000}?@[^@=]{1,2000}?)|({user}[^\s=]{1,2000}?))\s""",
      """msg=({alert_name}[^=]{1,2000}?)\s\w+=""",
      """informationThreatCategory=({alert_type}[^=]{1,2000}?)\s\w+=""",
      """CEF([^\|]{0,2000}\|){6}({alert_severity}[^|]{1,2000})""", 
      """flexString2=({alert_id}[^\s]{1,2000})[^~]{1,2000}?flexString2Label=incidentId""",
      """cs6=\[[^\]=]{1,2000}?\.({activity}[^\]]{1,2000})[^~]{1,2000}?cs6Label=Activity""",
    ]
 

}
```