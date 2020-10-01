#### Parser Content
```Java
{
Name = cef-securesphere-file-operations
  Vendor = Imperva
  Product = Imperva File Activity Monitoring (FAM)
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF""", """|SecureSphere|""", """|Audit.FAM|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wrt=({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wspt=({src_port}\d+)""",
    """\Wproto=({protocol}.+?)\s+(\w+=|$)""",
    """\Wduser=({account}.+?)\s+(\w+=|$)""",
    """\Wcs9=({outcome}.+?)\s+(\w+=|$)""",
    """\Wcs8=({accesses}.+?)\s+(\w+=|$)""",
    """\Wcs7=({file_path}.+?)\s+(\w+=|$)""",
    """\Wcs7=\\+({dest_host}[^\\]+)\\+({file_parent}([^\\]+\\)+?)({file_name}[^\\]+?(\.({file_ext}\w+))?)\s+(\w+=|$)""",
    """\Wcs6=({user}.+?)\s+(\w+=|$)""",
    """\Wcs5=({domain}.+?)\s+(\w+=|$)""",
    """\Wcs4=({event_code}.+?)\s+(\w+=|$)""",
    """\Wcs3=({service_name}.+?)\s+(\w+=|$)""",
    """\Wcs2=({server_group}.+?)\s+(\w+=|$)""",
    """\Wcs1=({policy}.+?)\s+(\w+=|$)""",
    """\Wcs12=(|({log_type}.+?))\s+(\w+=|$)""",
    """\Wcs11=(|({data_owner}.+?))\s+(\w+=|$)""",
    """\Wcs10=({access_type}.+?)\s+(\w+=|$)""",
    """\Wcat=({category}.+?)\s+(\w+=|$)""",
  ]
}
```