#### Parser Content
```Java
{
Name = s-fireeye-hx-alert-s-1
  Conditions = [ """msg""", """alert""","""product""" , """"HX""""]

s-fireeye-hx-alert-s = {
  Vendor = FireEye
  Product = FireEye Endpoint Security (HX)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """Event\/timestamp"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000})"{1,20}""",
    """"{1,20}_id"{1,20}:\s{1,100}({alert_id}\d{1,100})""",
    """\},\s{1,100}"{1,20}_id"{1,20}:\s{1,100}({alert_id}\d{1,100})""",
    """"{1,20}display_name"{1,20}:\s{1,100}"{1,20}({event_name}[^"]{1,2000})"{1,20}""",
    """"{1,20}hostname"{1,20}:\s{1,100}"{1,20}({src_host}[^"]{1,2000})"{1,20}""",
    """"{1,20}ip"{1,20}:\s{0,100}"{1,20}({src_ip}[^"]{1,2000})"{1,20}""",
    """"{1,20}agent_id"{1,20}:\s{1,100}"{1,20}({agent_id}[^"]{1,2000})"{1,20}""",
    """"{1,20}mac_address"{1,20}:\s{1,100}"{1,20}({src_mac_address}[^"]{1,2000})"{1,20}""",
    """Event\/process"{1,20}:\s{1,100}"{1,20}({process_name}[^"]{1,2000})"{1,20}""",
    """Event\/eventType"{1,20}:\s{1,100}"{1,20}({log_type}[^"]{1,2000})"{1,20}""",
    """Event\/processPath"{1,20}:\s{1,100}"{1,20}({path}[^"]{1,2000})"{1,20}""",
    """Event\/pid"{1,20}:\s{1,100}({pid}\d{1,100})""",
    """Event\/parentPid"{1,20}:\s{1,100}({parent_pid}\d{1,100})""",
    """Event\/parentProcess"{1,20}:\s{1,100}"{1,20}({parent_process}[^"]{1,2000})"{1,20}""",
    """Event\/parentProcessPath"{1,20}:\s{1,100}"{1,20}({parent_process_path}[^"]{1,2000})"{1,20}""",
    """Event\/md5"{1,20}:\s{1,100}"{1,20}({md5}[^"]{1,2000})"{1,20}""",
    """Event\/username"{1,20}:\s{1,100}"{1,20}(({domain}[^\\]{1,2000})\\+)?(SYSTEM|({user}[^"]{1,2000}))"{1,20}""",
    """Event\/processCmdLine"{1,20}:\s{1,100}"{1,20}({command_line}[^\}]{1,2000}?)"{0,20}(\s{1,100}|\s{0,20}"{0,20}\s{0,20})\}""",
    """"{1,20}uuid"{1,20}:\s{0,100}"{1,20}({uid}[^"]{1,2000})"{1,20}""",
    """"{1,20}domain"{1,20}:\s{1,100}"{1,20}({domain}[^"]{1,2000})"{1,20}""",
    """"{1,20}version"{1,20}:\s{0,100}"{1,20}({version}[^"]{1,2000})"{1,20}""",
    """"event_type"{1,20}:\s{0,100}"{1,20}({alert_type}[^"]{1,2000})"""",
    """"{1,20}appliance"{1,20}:\s{0,100}"{1,20}({host}[^"]{1,2000})"{1,20}"""
  ]
  DupFields = [ "event_name->alert_name" 
}
```