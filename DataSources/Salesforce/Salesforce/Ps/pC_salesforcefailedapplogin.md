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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """([^,]{0,2000},){0}"({user_email}[^\s",]{1,2000})""",
    """([^,]{0,2000},){1}"({src_ip}[a-fA-F:\d.]{1,2000})""",
    """([^,]{0,2000},){2}"({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100} (AM|PM|am|pm))""",
    """([^,]{0,2000},){4}"({outcome}[^"]{1,2000})""",
    """([^,]{0,2000},){4}"({failure_reason}[^"]{1,2000})""",
    """([^,]{0,2000},){5}"({browser}[^"]{1,2000})""",
    """([^,]{0,2000},){6}"({dest_host}[^"]{1,2000})""",
    """({app}salesforce)"""
  ]
}
```