#### Parser Content
```Java
{
okta-failed-app-login = {
    Vendor = Okta
    Product = Okta Adaptive MFA
    Lms = Splunk
    DataType = "failed-app-login"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """"IPAddress":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """"user":"({user_email}[^@"\s]{1,2000}?@[^@"\s]{1,2000})""",
      """"EventDetails":(\[|")({failure_reason}.*?)(\]|"),"\w+":"""
      """Sign-in Failed\s{1,100}-\s{1,100}({failure_reason}[^":,]{1,2000})""",
      """"Source":"({additional_info}[^"]{1,2000}?)"""",
      """"Source":\[({additional_info}[^\]]{1,2000})""",
      """"Host":"({host}[^"]{1,2000}?)"""",
      """"Host":\["({host}[^",]{1,2000})""",
      """({app}(o|O)kta)""",
      """"DisplayName":"({user_fullname}[^"]{1,2000}?\s[^"]{1,2000})""""
      """"DisplayName":\["({user_fullname}[^,"]{1,2000}?\s[^,"]{1,2000})"""
    ]
}
```