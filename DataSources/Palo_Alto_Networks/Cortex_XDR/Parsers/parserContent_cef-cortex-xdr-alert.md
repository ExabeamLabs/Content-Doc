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
     """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",   
   """CEF:.+?\|([^\|]+\|){4}({alert_name}[^\|]+)""",
    """\WexternalId=({alert_id}.+?)\s+""",
    """\Wcat=({alert_type}.*?)\s+""",
    """\Wcs2=({process}.*?)\s*cs2Label""",
    """\Wcs1=({process_name}.*?)\s+""",
    """fileHash=({sha256_sum}[A-Za-z0-9]+)\s""",
    """\Wcs2="({directory}.*?)"\s+""",
    """\Wshost=(({src_ip}\d+\.\d+\.\d+\.\d+)|({src_host}.*?))\s+""",
    """\Wsuser=(N/A|(({domain}[^\\]+)\\+)?({user}.+?))(\s+\w+=|\s*$)""",
    """\Wrequest=({additional_info}.*?)\s+"""
  ]
  DupFields = [ "process->path","directory->process_directory" ]
}
```