#### Parser Content
```Java
{
Name = fortiauthenticator-auth-successful
    Vendor = Fortinet
    Product = FortiAuthenticator
    Lms = Splunk
    DataType = "authentication-successful"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """subcategory="Authentication"""", """action="Login"""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
      """exabeam_host=({host}[^\s]+)""",
      """exabeam_host=({dest_host}[^\s]+)""",
      """nas="({dest_host}[^"]+)"""",
      """user="({user}[^"]+)"""",
      """status="({outcome}[^"]+)"""",
      """action="({event_name}[^"]+)"""",
      """status="Success" ({additional_info}.+?)\s*$""",
      """status="Failed" ({failure_reason}.+?)( to .*?)?\s*$""",
    ]
  }
```