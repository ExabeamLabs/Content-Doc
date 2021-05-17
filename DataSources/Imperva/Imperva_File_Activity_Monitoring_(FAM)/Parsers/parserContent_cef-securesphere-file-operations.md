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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wproto=({protocol}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=({account}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs9=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs8=({accesses}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs7=({file_path}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs7=\\+({dest_host}[^\\]{1,2000})\\+({file_parent}([^\\]{1,2000}\\)+?)({file_name}[^\\]{1,2000}?(\.({file_ext}\w+))?)\s{1,100}(\w+=|$)""",
    """\Wcs6=({user}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs5=({domain}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs4=({event_code}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs3=({service_name}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs2=({server_group}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs1=({policy}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs12=(|({log_type}.+?))\s{1,100}(\w+=|$)""",
    """\Wcs11=(|({data_owner}.+?))\s{1,100}(\w+=|$)""",
    """\Wcs10=({access_type}.+?)\s{1,100}(\w+=|$)""",
    """\Wcat=({category}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```