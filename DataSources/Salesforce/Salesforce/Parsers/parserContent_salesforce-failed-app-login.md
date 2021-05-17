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
    """([^,]{0,2000}
```