#### Parser Content
```Java
{
Name = cef-cortex-xdr-alert
  Vendor = Palo Alto Networks
  Product = Cortex XDR
  Lms = Direct
  DataType = "alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Palo Alto Networks|Cortex XDR""", """|Alert|""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
     """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",   
   """CEF:[^|]+?\|([^\|]+\|){4}({alert_name}[^\|]+)""",
    """\WexternalId=({alert_id}.+?)\s{1,100}""",
    """\Wcat=({alert_type}.*?)\s{1,100}""",
    """\Wcs2=({process}.*?)\s{0,100}cs2Label""",
    """\Wcs1=({process_name}.*?)\s{1,100}""",
    """fileHash=({sha256_sum}[A-Za-z0-9]+)\s""",
    """\Wcs2="({directory}.*?)"\s{1,100}""",
    """\Wshost=(({src_ip}\d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100})|({src_host}.*?))\s{1,100}""",
    """\Wsuser=(N/A|(({domain}[^\\]+)\\+)?({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrequest=({additional_info}.*?)\s{1,100}"""
  ]
  DupFields = [ "process->path","directory->process_directory" ]
}
```