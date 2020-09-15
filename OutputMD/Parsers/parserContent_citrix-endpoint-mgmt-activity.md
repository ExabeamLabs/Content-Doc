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
    """app.name="({app}[^"]+)"""",
    """client.ip="({src_ip}[^"]+)"""",
    """device.id="({src_host}[^"]+)"""",
    """event.action="({activity}[^"]+)"""",
    """event.status="({outcome}[^"]+)"""",
    """http.user-agent="({user_agent}[^"]+)"""",
    """\[os=({os}[^,\s]+)""",
    """session.id="({session_id}[^"]+)"""",
    """push.user="(({user_email}[^@"]+?@[^"]+)|(({domain}[^,\\]+)[\\]+({user}[^"]+))|({=user}[^"]+))""",
    """user.id="(({user_email}[^@"]+?@[^"]+)|(({domain}[^,\\]+)[\\]+({user}[^"]+))|({=user}[^"]+))""",
    """arg1":"({additional_info}[^"]+)"""
  ]   
}
```