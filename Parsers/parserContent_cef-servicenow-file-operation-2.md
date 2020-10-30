#### Parser Content
```Java
{
Name = cef-servicenow-file-operation-2
  Vendor = ServiceNow
  Product = ServiceNow
  Lms = ArcSight
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|""", """destinationServiceName=ServiceNow""" ]
  Fields = [
    """"sys_created_on":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """requestClientApplication=({app}.+?)\s+(\w+=|$)""",
    """\Wduser=(|({object}.+?))(\s+\w+=|\s*$)""",
    """\Wsuser=(|({user_email}[^\s@]+@({email_domain}[^\s@]+))|({user}.+?))(\s+\w+=|\s*$)""",
    """"srcip":"({src_ip}[^"]+)""",
    """"name":"({object}[^"]+)""",
    """\Wfname=(|({file_name}.+?(\.({file_ext}\w+))?))(\s+\w+=|\s*$)""",
    """"user(_name)?":"({user}[^"\s@]+)"""",
    """"user(_name)?":"({user_email}[^"\s@]+@({email_domain}[^"\s@]+))"""",
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """"queue":"({activity}[^"]+)""",
    """"parm1":"\s*(|-|({resource}.*?[^\\\s])\s*)",""",
  ]
  DupFields = [ "host->dest_host", "file_name->object" ]
}
```