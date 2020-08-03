#### Parser Content
```Java
{
Name = s-xenapp-ica-login
    Vendor = Citrix XenApp
  Product = Citrix XenApp
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "MM/dd/yyyy HH:mm:ss zzz"
    Conditions = [ "FarmName=","XenApp",""" State="Active""""]
    Fields = [
      """ServerName=\"+({host}[^"]+)"""",
      """CurrentTime=\"+({time}\d+/\d+/\d+ \d\d:\d\d:\d\d \w{3})""",
      """AccountName=\"+(({domain}[^\\]+)\\)?({user}[^"]+)""",
      """BrowserName=\"+({app}[^"]+)""",
      """ClientName=\"+({src_host}[^"]+)""",
      """ClientAddress=\"+({src_ip}[\d.]+)""",
      """UserName=\"+({user}[^"]+)"""
    ]
  }
```