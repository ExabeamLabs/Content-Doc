#### Parser Content
```Java
{
Name = citrix-endpoint-mgmt-activity
  Vendor = Citrix
  Product = Citrix Endpoint Management
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  DataType = "remote-logon"
  Conditions = [ """Original Address=""", """XMS - """, """Audit [""", """event.action="""]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)""",
    """Original Address=({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """app.name="({app}[^"]{1,2000})"""",
    """client.ip="({src_ip}[^"]{1,2000})"""",
    """device.id="({src_host}[^"]{1,2000})"""",
    """event.action="({activity}[^"]{1,2000})"""",
    """event.status="({outcome}[^"]{1,2000})"""",
    """http.user-agent="({user_agent}[^"]{1,2000})"""",
    """\[os=({os}[^,\s]{1,2000})""",
    """session.id="({session_id}[^"]{1,2000})"""",
    """push.user="(({user_email}[^@"]{1,2000}?@[^"]{1,2000})|(({domain}[^,\\]{1,2000})[\\]{1,2000}({user}[^"]{1,2000}))|({=user}[^"]{1,2000}))""",
    """user.id="(({user_email}[^@"]{1,2000}?@[^"]{1,2000})|(({domain}[^,\\]{1,2000})[\\]{1,2000}({user}[^"]{1,2000}))|({=user}[^"]{1,2000}))""",
    """arg1":"({additional_info}[^"]{1,2000})"""
  ]   


}
```