#### Parser Content
```Java
{
Name = symantec-web-activity-1
  Vendor = Symantec
  Product = Symantec WSS
  Lms = Syslog
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """destinationServiceName =Symantec WSS""", """requestClientApplication=Broadcom WSS API""", """|Skyformation|""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\s[^\s]{1,2000}\sSkyformation""",
    """cs6=.+?\d\d:\d\d:\d\d,\s{0,100}({host}[^,\s]{1,2000})""",
    """\s{0,100}({failure_reason}[^,]{1,2000}),\s{0,100}({action}OBSERVED|PROXIED|DENIED),\s{0,100}(?:-|({category}[^,]{1,2000})),\s{0,100}(?:-|({referrer}[^,]{1,2000})),\s{0,100}(?:-|({result_code}\d{1,100})),\s{0,100}(?:-|({proxy_action}[^,]{1,2000})),\s{0,100}(?:-|unknown|({method}[^,]{1,2000})),\s{0,100}(?:-|({mime}[^,]{1,2000})),\s{0,100}(?:-|({protocol}[^,]{1,2000})),\s{0,100}(?:-|({web_domain}[^,]{1,2000})),\s{0,100}(?:-|({dest_port}[^,]{1,2000})),\s{0,100}(?:-|({uri_path}[^,\s]{1,2000})),.+?,\s[^,]{1,2000

}
```