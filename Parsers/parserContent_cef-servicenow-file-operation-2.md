#### Parser Content
```Java
{
Name = cef-servicenow-file-operation-2
  Vendor = ServiceNow
  Product = ServiceNow
  Lms = ArcSight
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|""", """destinationServiceName=ServiceNow""", """cat=""", """"sys_created_on"""", """"sys_created_by""""]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"sys_created_on"+:"+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """requestClientApplication=({app}[^=]+?)\s+(\w+=|$)""",
    """\Wduser=(|({object}[^=]+?))(\s+\w+=|\s*$)""",
    """\Wsuser=(anonymous|system|({user_email}[^\s@]+@({email_domain}[^\s@]+))|({user}[^=]+?))(\s+\w+=|\s*$)""",
    """"srcip":"({src_ip}[^"]+)""",
    """"name"+:"+({object}[^"]+)""",
    """\Wfname=(|-|({file_name}.+?(\.({file_ext}\w+))?))(\s+\w+=|\s*$)""",
    """"user(_name)?":"(anonymous|system|({user}[^"\s@]+))"""",
    """"user(_name)?":"(anonymous|system|({user_email}[^"\s@]+@({email_domain}[^"\s@]+)))"""",
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """"queue":"({activity}[^"]+)""",
    """"parm1"+:"+\s*(|-|({resource}[^"]+))"+,""",
    """"(instance|documentkey)"+:"+({object}[^"]+)""",
    """"tablename"+:"+({table_name}[^"]+)"+,""",
    """"table"+:"+({table}[^"]+)"+,""",
    """dproc=({event_name}[^=]+?)(\s\w+=|$)""",
    """msg=({additional_info}[^=]+?)(\s\w+=|$)""",
    """"parm2"+:"+({action}[^"]+)"+,"""
  ]
  DupFields = [ "host->dest_host", "file_name->object" ]
}
```