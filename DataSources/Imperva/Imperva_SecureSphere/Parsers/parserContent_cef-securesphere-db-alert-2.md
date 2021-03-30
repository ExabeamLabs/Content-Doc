#### Parser Content
```Java
{
Name = cef-securesphere-db-alert-2
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = ArcSight
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|Imperva Inc.|SecureSphere""", """cat=Alert""", """cs1Label=ServerGroup""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wrt=({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d)""",
    """\Wsrc=\s*(0.0.0.0|({src_ip}[A-Fa-f:\d.]+))""",
    """\Wdst=\s*(0.0.0.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """\Wduser=(?:n\/a|(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+?))\s+(\w+=|$)""",
    """\Wcs1=(|({server_group}.+?))\s+(\w+=|$)""",
    """\Wcs2=(|({service_name}.+?))\s+(\w+=|$)""",
    """\Wcs3=(|({app}.+?))\s+(\w+=|$)""",
    """CEF:([^\|]*\|){5}({alert_name}[^\|]+)""",
    """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```