#### Parser Content
```Java
{
Name = f5-vpn-os
    Vendor = F5
    Product = F5 BIG-IP
    Lms = Splunk
    DataType = "vpn-start"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """01490007:6:""", """: Session variable 'session.client.platform' set to '""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[^\s]{1,2000})""",
      """:Common:({session_id}[^:]{1,2000})""",
      """platform' set to '({os}[^'"]{1,2000})'""",
    ]


}
```