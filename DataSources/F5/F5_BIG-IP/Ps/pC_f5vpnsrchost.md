#### Parser Content
```Java
{
Name = f5-vpn-srchost
    Vendor = F5
    Product = F5 BIG-IP
    Lms = Splunk
    DataType = "vpn-start"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """01490007:6:""", """: Session variable 'session.client.hostname' set to '""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[^\s]{1,2000})""",
      """:Common:({session_id}[^:]{1,2000})""",
      """hostname' set to '({src_host}[\w\-.]{1,2000})""",
    ]


}
```