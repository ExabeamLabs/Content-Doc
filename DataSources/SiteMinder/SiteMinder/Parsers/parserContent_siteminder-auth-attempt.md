#### Parser Content
```Java
{
Name = siteminder-auth-attempt
    Vendor = SiteMinder
    Product = SiteMinder
    Lms = Splunk
    DataType = "authentication-attempt"
    TimeFormat = "MMM dd',' yyyy',' HH:mm:ss a"
    Conditions = [""""CA SiteMinder@""", """Authentication"""]
    Fields = [
      """"({auth_type}[^"]+?)","CA SiteMinder@"""
      """"CA SiteMinder@.*?",("[^"]+?",){1}"({time}\w+ \d{1,100}
```