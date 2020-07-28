#### Parser Content
```Java
{
Name = ipsec-vpn-user
  Vendor = SecureNet
  Product = SecureNet
  Lms = Direct
  DataType = "vpn-user"
  TimeFormat = "yyyy:MM:dd-HH:mm:ss"
  Conditions = [ """pppd-l2tp[""", """sub="vpn"""", """username=""""  ]
  Fields = [
    """({time}\d\d\d\d:\d\d:\d\d\-\d\d:\d\d:\d\d)\s+({host}[^\s]+)""",
    """\Wid="({event_code}\d+)""",
    """\Wevent="({event_name}[^"]+)"""",
    """\Wusername="({user}[^"]+)"""",
    """\Wsrcip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """\Wvirtual_ip="({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
  ]
  DupFields = ["user->account"]
}

{
  Name = s-cylance-app-activity
  Vendor = Cylance
  Product = PROTECT
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """, Event Name:""", """, Message:""", """Event Type: AuditLog""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)[^\s]*\s+[^\s]+\s+({app}[^\s]+)\s""",
    """\w+\s+\d+ \d\d:\d\d:\d\d ({host}[a-fA-F\d.:]+)""",
    """\[({host}[\w\-.]+)\]\s*Event Type:""",
    """\sEvent Name:\s*({activity}[^,]+),""",
    """\sMessage:.+?[^,:]+(Assigned|Changed):\s*({additional_info}[^:,;]+)""",
    """\sUser:\s*(|({user_fullname}.+?))\s*\(({user_email}[^@\s\)]+@[^@\s\)]+)\)""",
    """\sSource IP:\s*({src_ip}[a-fA-F\d\.:]+)""",
    """\sProvider:\s*({login_type}[^,]+)""",
    """\sDevice:\s*({object}[^;]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```