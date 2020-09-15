#### Parser Content
```Java
{
Name = windows-dns-response-2
  DataType = "dns-response"
  Conditions = [ """Query/Response=R""", """Flags (char codes)=""", """Question Type=""" ]
  DupFields = [ "dest_ip->dest_host" ]
}
```