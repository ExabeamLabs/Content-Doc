#### Parser Content
```Java
{
Name = salesforce-failed-app-login
  Vendor = Salesforce
  Product = Salesforce
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "MM/dd/yyyy hh:mm a"
  Conditions = [ ""","Invalid Password"""", ""","login.salesforce.com"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """([^,]*,){0}"({user_email}[^\s",]+)""",
    """([^,]*,){1}"({src_ip}[a-fA-F:\d.]+)""",
    """([^,]*,){2}"({time}\d+\/\d+\/\d+ \d+:\d+ (AM|PM|am|pm))""",
    """([^,]*,){4}"({outcome}[^"]+)""",
    """([^,]*,){4}"({failure_reason}[^"]+)""",
    """([^,]*,){5}"({browser}[^"]+)""",
    """([^,]*,){6}"({dest_host}[^"]+)""",
    """({app}salesforce)"""
  ]
}
```