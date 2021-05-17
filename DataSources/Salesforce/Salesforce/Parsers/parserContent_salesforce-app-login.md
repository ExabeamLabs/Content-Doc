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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """([^,]{0,2000}
```