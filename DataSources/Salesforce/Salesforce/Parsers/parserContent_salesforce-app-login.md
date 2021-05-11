#### Parser Content
```Java
{
Name = salesforce-app-login
  Vendor = Salesforce
  Product = Salesforce
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "MM/dd/yyyy hh:mm a"
  Conditions = [ ""","Success"""", ""","login.salesforce.com"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """([^,]*,){0}"({user_email}[^@]+({email_domain}[^\s",]+))""",
    """([^,]*,){1}"({src_ip}[a-fA-F:\d.]+)""",
    """([^,]*,){2}"({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100} (AM|PM|am|pm))""",
    """([^,]*,){4}"({outcome}[^"]+)""",
    """([^,]*,){5}"({browser}[^"]+)""",
    """([^,]*,){6}"({dest_host}[^"]+)""",
    """({app}salesforce)"""
  ]
}
```