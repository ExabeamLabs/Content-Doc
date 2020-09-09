#### Parser Content
```Java
{
Name = windows-dns-query-2
  DataType = "dns-query"
  Conditions = [ """Query/Response=Q""", """Flags (char codes)=""", """Question Type=""" ]
  DupFields = [ "dest_ip->dest_host" ]
}
```