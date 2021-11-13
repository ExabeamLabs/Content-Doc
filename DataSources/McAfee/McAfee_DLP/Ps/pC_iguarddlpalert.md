#### Parser Content
```Java
{
Name = iguard-dlp-alert
    Vendor = McAfee
    Product = McAfee DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = ["CEF:", "|McAfee|iGuard"]
    Fields = [ """\send=({time}\w{3} \d{1,100} \d{1,100} \d\d:\d\d:\d\d)""",
      """\d\d:\d\d:\d\d ({host}[^\s]{1,2000})""",
      """CEF([^\|]{0,2000}\|){5}({alert_name}[^|]{1,2000})""",
      """CEF([^\|]{0,2000}\|){6}({alert_severity}[^|]{1,2000})""",
      """cs1=({alert_type}.+?)\s{1,100}cs1Label""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """fsize=({bytes}\d{1,100})""",
      """app=({protocol}.+?)\s{1,100}\w+=""",
      """app=SMTP.+?suser=({sender}[^\s]{1,2000})""",
      """app=SMTP.+?duser=({recipients}.*?)\s{1,100}\w+=""",
      """app=SMTP.+?duser=({external_address}[^\s,]{1,2000})""",
      """app=SMTP.+?cs2="{0,20}({subject}[^"]{0,2000})""",
      """app=SMTP.+?fname=(?:Unknown|({attachment}.+?))\s{1,100}$""",
      """app=HTTP.+?fname=({target}.+?)\s{1,100}$""",
    ]
  

}
```