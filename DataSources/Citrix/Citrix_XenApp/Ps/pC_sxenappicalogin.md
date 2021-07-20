#### Parser Content
```Java
{
Name = s-xenapp-ica-login
    Vendor = Citrix
    Product = Citrix XenApp
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "MM/dd/yyyy HH:mm:ss zzz"
    Conditions = [ "FarmName=","XenApp",""" State="Active""""]
    Fields = [
      """ServerName=\"{1,20}({host}[^"]{1,2000})"""",
      """CurrentTime=\"{1,20}({time}\d{1,100}/\d{1,100}/\d{1,100} \d\d:\d\d:\d\d \w{3})""",
      """AccountName=\"{1,20}(({domain}[^\\]{1,2000})\\)?({user}[^"]{1,2000})""",
      """BrowserName=\"{1,20}({app}[^"]{1,2000})""",
      """ClientName=\"{1,20}({src_host}[^"]{1,2000})""",
      """ClientAddress=\"{1,20}({src_ip}[\d.]{1,2000})""",
      """UserName=\"{1,20}({user}[^"]{1,2000})"""
    ]
  }
```