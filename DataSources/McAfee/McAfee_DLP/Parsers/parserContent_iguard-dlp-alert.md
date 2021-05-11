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
      """\d\d:\d\d:\d\d ({host}[^\s]+)""",
      """CEF([^\|]*\|){5}({alert_name}[^|]+)""",
      """CEF([^\|]*\|){6}({alert_severity}[^|]+)""",
      """cs1=({alert_type}.+?)\s{1,100}cs1Label""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """fsize=({bytes}\d{1,100})""",
      """app=({protocol}.+?)\s{1,100}\w+=""",
      """app=SMTP.+?suser=({sender}[^\s]+)""",
      """app=SMTP.+?duser=({recipients}.*?)\s{1,100}\w+=""",
      """app=SMTP.+?duser=({external_address}[^\s,]+)""",
      """app=SMTP.+?duser=(?:[^@]+@)({external_domain}[^,\s]+)""",
      """app=SMTP.+?cs2="{0,20}({subject}[^"]*)""",
      """app=SMTP.+?fname=(?:Unknown|({attachment}.+?))\s{1,100}$""",
      """app=HTTP.+?fname=({target}.+?)\s{1,100}$""",
    ]
  }
```